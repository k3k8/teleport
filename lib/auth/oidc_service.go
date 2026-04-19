/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	zoidc "github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/observability/otelhttp"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// ossOIDCService implements OIDCService using standard OIDC/OAuth2 without
// requiring an enterprise license. It follows the same pattern as github.go.
type ossOIDCService struct {
	server *Server
}

// newOSSoidcService creates an OIDCService implementation for use in OSS builds.
func newOSSoidcService(s *Server) *ossOIDCService {
	return &ossOIDCService{server: s}
}

// Ensure ossOIDCService implements OIDCService at compile time.
var _ OIDCService = (*ossOIDCService)(nil)

// CreateOIDCAuthRequest implements OIDCService. It generates a redirect URL
// to the OIDC provider's authorization endpoint and persists the request state.
func (o *ossOIDCService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := o.getConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !req.CreateWebSession {
		ceremonyType := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremonyType = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremonyType, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	dc, err := client.Discover(ctx, connector.GetIssuerURL(), otelhttp.DefaultClient)
	if err != nil {
		return nil, trace.Wrap(err, "discovering OIDC provider at %q", connector.GetIssuerURL())
	}

	req.StateToken, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	oauthCfg := o.oauthConfig(connector, dc, req.ProxyAddress)
	req.RedirectURL = oauthCfg.AuthCodeURL(req.StateToken)

	if req.LoginHint != "" {
		req.RedirectURL += "&login_hint=" + url.QueryEscape(req.LoginHint)
	}

	o.server.logger.DebugContext(ctx, "Creating OIDC auth request", "redirect_url", req.RedirectURL)

	if err := o.server.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// CreateOIDCAuthRequestForMFA is not supported in this OSS implementation.
func (o *ossOIDCService) CreateOIDCAuthRequestForMFA(_ context.Context, _ types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return nil, trace.NotImplemented("OIDC MFA re-authentication is not supported in this build")
}

// ValidateOIDCAuthCallback implements OIDCService. It validates the callback
// from the OIDC provider, exchanges the authorization code for tokens, verifies
// the ID token, maps claims to roles, and creates or updates the Teleport user.
func (o *ossOIDCService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	if errParam := q.Get("error"); errParam != "" {
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("invalid_request", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "OIDC provider returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		return nil, trace.OAuth2("invalid_request", "code query param must be set", q)
	}

	stateToken := q.Get("state")
	if stateToken == "" {
		return nil, trace.OAuth2("invalid_request", "missing state query param", q)
	}

	req, err := o.server.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "failed to get OIDC auth request")
	}

	connector, err := o.getConnector(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "failed to get OIDC connector")
	}

	dc, err := client.Discover(ctx, connector.GetIssuerURL(), otelhttp.DefaultClient)
	if err != nil {
		return nil, trace.Wrap(err, "discovering OIDC provider at %q", connector.GetIssuerURL())
	}

	oauthCfg := o.oauthConfig(connector, dc, req.ProxyAddress)

	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		return nil, trace.Wrap(err, "exchanging OIDC authorization code")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, trace.BadParameter("OIDC provider did not return an id_token")
	}

	ks := rp.NewRemoteKeySet(otelhttp.DefaultClient, dc.JwksURI)
	verifier := rp.NewIDTokenVerifier(connector.GetIssuerURL(), connector.GetClientID(), ks)
	claims, err := rp.VerifyIDToken[*zoidc.IDTokenClaims](ctx, rawIDToken, verifier)
	if err != nil {
		return nil, trace.Wrap(err, "verifying OIDC ID token")
	}

	o.server.logger.DebugContext(ctx, "OIDC claims received",
		slog.String("subject", claims.Subject),
		slog.String("email", claims.Email),
	)

	traits := oidcClaimsToTraits(claims)

	username := extractOIDCUsername(connector, claims)
	if username == "" {
		return nil, trace.BadParameter(
			"OIDC connector %q: could not determine username from claims; set username_claim on the connector",
			connector.GetName(),
		)
	}

	_, roles := services.TraitsToRoles(connector.GetTraitMappings(), traits)
	if len(roles) == 0 {
		return nil, trace.AccessDenied(
			"OIDC connector %q: no roles mapped from claims; check claims_to_roles configuration",
			connector.GetName(),
		)
	}

	evaluationOutput, err := o.server.GetLoginRuleEvaluator().Evaluate(ctx, &loginrule.EvaluationInput{Traits: traits})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	traits = evaluationOutput.Traits

	fetchedRoles, err := services.FetchRoles(roles, o.server, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := fetchedRoles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	sessionTTL := utils.MinTTL(roleTTL, req.CertTTL)

	user, err := o.upsertOIDCUser(ctx, req, connector, username, claims.Subject, roles, traits, sessionTTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := o.server.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := o.server.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	identity := types.ExternalIdentity{
		ConnectorID: connector.GetName(),
		Username:    username,
	}

	if req.SSOTestFlow {
		return &authclient.OIDCAuthResponse{
			Req:      oidcAuthRequestFromProto(req),
			Identity: identity,
			Username: username,
		}, nil
	}

	return o.makeOIDCAuthResponse(ctx, req, userState, identity, sessionTTL)
}

// getConnector retrieves the OIDC connector. In test flow, the connector spec
// is embedded directly in the auth request.
func (o *ossOIDCService) getConnector(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow {
		if req.ConnectorSpec == nil {
			return nil, trace.BadParameter("ConnectorSpec cannot be nil for SSOTestFlow")
		}
		if req.ConnectorID == "" {
			return nil, trace.BadParameter("ConnectorID cannot be empty")
		}
		connector, err := types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	connector, err := o.server.GetOIDCConnector(ctx, req.ConnectorID, true /* withSecrets */)
	return connector, trace.Wrap(err)
}

// oauthConfig builds an oauth2.Config from a connector and discovery document.
func (o *ossOIDCService) oauthConfig(connector types.OIDCConnector, dc *zoidc.DiscoveryConfiguration, proxyAddress string) oauth2.Config {
	scopes := append([]string{"openid", "email"}, connector.GetScope()...)
	return oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		RedirectURL:  selectOIDCRedirectURL(connector.GetRedirectURLs(), proxyAddress),
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  dc.AuthorizationEndpoint,
			TokenURL: dc.TokenEndpoint,
		},
	}
}

// selectOIDCRedirectURL picks the redirect URL that best matches the proxy
// address. Falls back to the first URL if no match is found.
func selectOIDCRedirectURL(redirectURLs []string, proxyAddress string) string {
	if len(redirectURLs) == 0 {
		return ""
	}
	if proxyAddress == "" {
		return redirectURLs[0]
	}
	// Strip port for host comparison.
	host := proxyAddress
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	for _, u := range redirectURLs {
		if strings.Contains(u, host) {
			return u
		}
	}
	return redirectURLs[0]
}

// upsertOIDCUser creates or updates the Teleport user record from OIDC claims.
func (o *ossOIDCService) upsertOIDCUser(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	connector types.OIDCConnector,
	username, subject string,
	roles []string,
	traits map[string][]string,
	sessionTTL time.Duration,
) (types.User, error) {
	o.server.logger.DebugContext(ctx, "Generating dynamic OIDC identity",
		"connector", connector.GetName(),
		"username", username,
		"roles", roles,
	)

	expires := o.server.GetClock().Now().UTC().Add(sessionTTL)
	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  roles,
			Traits: traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: connector.GetName(),
				Username:    username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: o.server.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       connector.GetName(),
					Identity: username,
				},
			},
		},
	}

	if req.SSOTestFlow {
		return user, nil
	}

	existingUser, err := o.server.Services.GetUser(ctx, username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user", username)
		}
		user.SetRevision(existingUser.GetRevision())
		if _, err := o.server.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := o.server.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

// makeOIDCAuthResponse builds the final auth response including an optional
// web session and/or SSH/TLS certificates.
func (o *ossOIDCService) makeOIDCAuthResponse(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	userState services.UserState,
	identity types.ExternalIdentity,
	sessionTTL time.Duration,
) (*authclient.OIDCAuthResponse, error) {
	auth := authclient.OIDCAuthResponse{
		Req:      oidcAuthRequestFromProto(req),
		Identity: identity,
		Username: userState.GetName(),
	}

	if req.CreateWebSession {
		session, err := o.server.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            o.server.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create web session")
		}
		auth.Session = session
	}

	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := o.server.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
			Scope:                   req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create session certificate")
		}

		clusterName, err := o.server.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster name")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		authority, err := o.server.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster host CA")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	if opts, err := o.server.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = opts
	} else {
		o.server.logger.WarnContext(ctx, "Failed to calculate client options for OIDC login",
			"username", userState.GetName(), "error", err)
	}

	return &auth, nil
}

// oidcClaimsToTraits converts zitadel IDTokenClaims into the traits map used
// for role mapping. Standard claims (sub, email, etc.) are included alongside
// any extra claims present in the token.
func oidcClaimsToTraits(claims *zoidc.IDTokenClaims) map[string][]string {
	traits := map[string][]string{
		"sub":   {claims.Subject},
		"email": {claims.Email},
	}
	if claims.PreferredUsername != "" {
		traits["preferred_username"] = []string{claims.PreferredUsername}
	}
	if claims.Name != "" {
		traits["name"] = []string{claims.Name}
	}
	for k, v := range claims.Claims {
		if vals := oidcClaimToStringSlice(v); len(vals) > 0 {
			traits[k] = vals
		}
	}
	return traits
}

// extractOIDCUsername returns the username to use for the Teleport user.
// It uses connector.GetUsernameClaim() if set, falling back to
// preferred_username, email, and finally sub.
func extractOIDCUsername(connector types.OIDCConnector, claims *zoidc.IDTokenClaims) string {
	if uc := connector.GetUsernameClaim(); uc != "" {
		// Check standard profile fields first.
		switch uc {
		case "preferred_username":
			if claims.PreferredUsername != "" {
				return claims.PreferredUsername
			}
		case "email":
			if claims.Email != "" {
				return claims.Email
			}
		case "sub":
			if claims.Subject != "" {
				return claims.Subject
			}
		default:
			// Fall through to extra claims map.
		}
		// Check extra claims for non-standard claim names.
		if v, ok := claims.Claims[uc]; ok {
			if s := fmt.Sprintf("%v", v); s != "" && s != "<nil>" {
				return s
			}
		}
	}

	// Default fallback: preferred_username → email → sub.
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	if claims.Email != "" {
		return claims.Email
	}
	return claims.Subject
}

// oidcClaimToStringSlice converts an OIDC claim value (which may be a string,
// []interface{}, or other type) into a []string suitable for trait mapping.
func oidcClaimToStringSlice(v any) []string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, elem := range val {
			if s := fmt.Sprintf("%v", elem); s != "" && s != "<nil>" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	default:
		s := fmt.Sprintf("%v", v)
		if s == "" || s == "<nil>" {
			return nil
		}
		return []string{s}
	}
}

// oidcAuthRequestFromProto converts types.OIDCAuthRequest to the authclient
// variant embedded in response structs.
func oidcAuthRequestFromProto(req *types.OIDCAuthRequest) authclient.OIDCAuthRequest {
	return authclient.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		CSRFToken:         req.CSRFToken,
		SSHPubKey:         req.SshPublicKey,
		TLSPubKey:         req.TlsPublicKey,
		CreateWebSession:  req.CreateWebSession,
		ClientRedirectURL: req.ClientRedirectURL,
	}
}
