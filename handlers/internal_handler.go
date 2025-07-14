package handlers

import (
	"PumpProxy/config"
	"PumpProxy/kube"
	"PumpProxy/logging"
	"PumpProxy/security"
	"PumpProxy/templates"
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type InternalHandler struct {
	BaseHandler
	proxyConfig  *config.ProxyConfig
	oidcVerifier *oidc.IDTokenVerifier
	kubeClient   *kube.KubeClient
	oidcContext  context.Context
	oauthConfig  oauth2.Config
}

func NewInternalHandler(prefix string, config *config.ProxyConfig, kubecClient *kube.KubeClient) *InternalHandler {
	proxyConfig := config
	oidcContext := context.Background()

	provider, err := oidc.NewProvider(oidcContext, proxyConfig.Oidc.OidcURL)
	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: proxyConfig.Oidc.OidcClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID:     proxyConfig.Oidc.OidcClientID,
		ClientSecret: proxyConfig.Oidc.OidcClientSecret,
		RedirectURL:  proxyConfig.Oidc.OidcRedirectURL,
		Scopes:       []string{oidc.ScopeOpenID},
		Endpoint:     provider.Endpoint(),
	}

	return &InternalHandler{
		BaseHandler:  BaseHandler{prefix: prefix},
		oidcVerifier: verifier,
		oauthConfig:  oauthConfig,
		oidcContext:  oidcContext,
		proxyConfig:  proxyConfig,
		kubeClient:   kubecClient,
	}
}

func (h *InternalHandler) RegisterEndpoints() {
	http.Handle(h.prefix+"/sign_in", http.HandlerFunc(h.signInHandler))
	http.Handle(h.prefix+"/sign_out", http.HandlerFunc(h.signOutHandler))
	http.Handle(h.prefix+"/auth", http.HandlerFunc(h.authHandler))
	http.Handle(h.prefix+"/callback", http.HandlerFunc(h.callbackHandler))
}

func (h *InternalHandler) signInHandler(w http.ResponseWriter, r *http.Request) {
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
	page, err := templates.ReadSigninPage()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Write(page)
}

func (h *InternalHandler) signOutHandler(w http.ResponseWriter, r *http.Request) {
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
	page, err := templates.ReadSigninPage()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.deleteCookies(w, r)
	w.Write(page)
}

func (h *InternalHandler) authHandler(w http.ResponseWriter, r *http.Request) {
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
	h.authWithOIDC(w, r)
}

func (h *InternalHandler) deleteCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
			SameSite: cookie.SameSite,
		})
	}
}

func (h *InternalHandler) setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func (h *InternalHandler) authWithOIDC(w http.ResponseWriter, r *http.Request) {
	state, err := security.RandString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := security.RandString(16)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.setCallbackCookie(w, r, "state", state)
	h.setCallbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, h.oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusSeeOther)

}

func (h *InternalHandler) getServiceAccountToken(serviceAccountName string) (string, error) {
	tokenDuration := int64(h.proxyConfig.TokenDuration.Seconds())
	token, err := h.kubeClient.GenerateServiceAccountToken(serviceAccountName, h.proxyConfig.ServiceAccountNamespace, tokenDuration)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (h *InternalHandler) acquireServiceAccount(groups []string, email string) (string, error) {
	// In the future email may be used in mapping logic, currently only groups are used
	serviceAccountName := ""

	for _, k := range groups {
		if val, ok := h.proxyConfig.GroupMapping[k]; ok {
			serviceAccountName = val
			break
		}
	}

	if serviceAccountName == "" {
		return "", errors.New("no service account found for user groups")
	}
	return serviceAccountName, nil
}

func (h *InternalHandler) setSATokenCookie(w http.ResponseWriter, saToken string) {
	encryptedSaToken, err := security.Encrypt([]byte(saToken), h.proxyConfig.EncryptionKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	encodedSaToken := base64.StdEncoding.EncodeToString(encryptedSaToken)
	claims := jwt.MapClaims{
		"iss":                   "pump-proxy",
		"exp":                   time.Now().Add(h.proxyConfig.TokenDuration).Unix(),
		"service_account_token": encodedSaToken,
	}
	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedAuthToken, err := authToken.SignedString(h.proxyConfig.JWTSecret)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedAuthToken,
		Path:     "/",
		HttpOnly: h.proxyConfig.Cookie.HttpOnly,
		Secure:   h.proxyConfig.Cookie.Secure,
		SameSite: h.proxyConfig.Cookie.SameSite,
		Expires:  time.Now().Add(h.proxyConfig.TokenDuration),
	})
}

func (h *InternalHandler) callbackHandler(w http.ResponseWriter, r *http.Request) {
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := h.oauthConfig.Exchange(h.oidcContext, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := h.oidcVerifier.Verify(h.oidcContext, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	// Extract claims from idToken
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract groups and email
	var groups []string
	if groupsClaim, ok := claims["groups"].([]interface{}); ok {
		for _, group := range groupsClaim {
			if groupStr, ok := group.(string); ok {
				groups = append(groups, groupStr)
			}
		}
	}
	email, _ := claims["email"].(string)

	serviceAccountName, err := h.acquireServiceAccount(groups, email)
	if err != nil {
		http.Error(w, "Failed to acquire service account: "+err.Error(), http.StatusUnauthorized)
		return
	}

	saToken, err := h.getServiceAccountToken(serviceAccountName)
	if err != nil {
		http.Error(w, "Failed to get service account token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	for _, name := range []string{"nonce", "state"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
	h.setSATokenCookie(w, saToken)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
