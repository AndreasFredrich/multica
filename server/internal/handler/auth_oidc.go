package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
)

type OIDCLoginRequest struct {
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
}

type oidcDiscovery struct {
	TokenEndpoint    string `json:"token_endpoint"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

type oidcUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// OIDCLogin completes a generic OpenID Connect authorization-code login (e.g.
// against the Agentic360 IAM). The browser performs the authorize redirect with
// PKCE and posts the returned code + code_verifier here for a server-side token
// exchange, mirroring the Google login flow. Endpoints are resolved via the
// issuer's discovery document so the same handler works for any OIDC provider.
func (h *Handler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	var req OIDCLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER")), "/")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	if issuer == "" || clientID == "" {
		writeError(w, http.StatusServiceUnavailable, "OIDC login is not configured")
		return
	}

	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = os.Getenv("OIDC_REDIRECT_URI")
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	disc, err := oidcDiscover(ctx, issuer)
	if err != nil {
		slog.Error("oidc discovery failed", "issuer", issuer, "error", err)
		writeError(w, http.StatusBadGateway, "failed to reach identity provider")
		return
	}

	// Exchange authorization code for tokens.
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {req.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	tokReq, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.Header.Set("Accept", "application/json")

	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		slog.Error("oidc token exchange failed", "error", err)
		writeError(w, http.StatusBadGateway, "failed to exchange code with identity provider")
		return
	}
	defer tokResp.Body.Close()
	tokBody, _ := io.ReadAll(tokResp.Body)
	if tokResp.StatusCode != http.StatusOK {
		slog.Error("oidc token exchange returned error", "status", tokResp.StatusCode, "body", string(tokBody))
		writeError(w, http.StatusBadRequest, "failed to exchange code with identity provider")
		return
	}
	var tok oidcTokenResponse
	if err := json.Unmarshal(tokBody, &tok); err != nil || tok.AccessToken == "" {
		writeError(w, http.StatusBadGateway, "invalid token response from identity provider")
		return
	}

	// Fetch user info.
	uiReq, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.UserinfoEndpoint, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	uiReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uiReq.Header.Set("Accept", "application/json")
	uiResp, err := http.DefaultClient.Do(uiReq)
	if err != nil {
		slog.Error("oidc userinfo fetch failed", "error", err)
		writeError(w, http.StatusBadGateway, "failed to fetch user info from identity provider")
		return
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "failed to fetch user info from identity provider")
		return
	}
	var info oidcUserInfo
	if err := json.NewDecoder(uiResp.Body).Decode(&info); err != nil {
		writeError(w, http.StatusBadGateway, "failed to parse user info from identity provider")
		return
	}

	email := strings.ToLower(strings.TrimSpace(info.Email))
	if email == "" {
		writeError(w, http.StatusBadRequest, "identity provider did not return an email")
		return
	}

	user, err := h.findOrCreateUser(ctx, email)
	if err != nil {
		if errors.Is(err, errSignupNotAllowed) {
			writeError(w, http.StatusForbidden, "registration is restricted to approved email domains")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	tokenString, err := h.issueJWT(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	if err := auth.SetAuthCookies(w, tokenString); err != nil {
		slog.Warn("failed to set auth cookies", "error", err)
	}
	if h.CFSigner != nil {
		for _, cookie := range h.CFSigner.SignedCookies(time.Now().Add(30 * 24 * time.Hour)) {
			http.SetCookie(w, cookie)
		}
	}

	slog.Info("user logged in via oidc", "user_id", uuidToString(user.ID), "email", user.Email)
	writeJSON(w, http.StatusOK, LoginResponse{
		Token: tokenString,
		User:  userToResponse(user),
	})
}

func oidcDiscover(ctx context.Context, issuer string) (oidcDiscovery, error) {
	var d oidcDiscovery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return d, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return d, err
	}
	if d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		return d, fmt.Errorf("discovery document missing token or userinfo endpoint")
	}
	return d, nil
}
