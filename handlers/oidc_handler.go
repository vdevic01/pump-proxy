package handlers

import (
	"PumpProxy/config"
	"PumpProxy/logging"
	"PumpProxy/security"
	saservice "PumpProxy/services/sa-service"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCHandler struct {
	SAHandler
	proxyConfig  *config.ProxyConfig
	oidcVerifier *oidc.IDTokenVerifier
	saService    *saservice.SAService
	oidcContext  context.Context
	oauthConfig  oauth2.Config
}

func NewOIDCHandler(prefix string, config *config.ProxyConfig, saService *saservice.SAService) *OIDCHandler {
	proxyConfig := config
	oidcContext := context.Background()

	provider, err := oidc.NewProvider(oidcContext, proxyConfig.Oidc.IdpURL)
	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: proxyConfig.Oidc.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID:     proxyConfig.Oidc.ClientID,
		ClientSecret: proxyConfig.Oidc.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/pumpproxy/callback", proxyConfig.Oidc.RedirectURL),
		Scopes:       []string{oidc.ScopeOpenID},
		Endpoint:     provider.Endpoint(),
	}

	return &OIDCHandler{
		SAHandler:    *NewSAHandler(prefix, saService),
		oidcVerifier: verifier,
		oauthConfig:  oauthConfig,
		oidcContext:  oidcContext,
		proxyConfig:  proxyConfig,
		saService:    saService,
	}
}

func (h *OIDCHandler) RegisterEndpoints() {
	http.Handle(h.prefix+"/auth", http.HandlerFunc(h.authHandler))
	http.Handle(h.prefix+"/callback", http.HandlerFunc(h.callbackHandler))
}

func (h *OIDCHandler) setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func (h *OIDCHandler) authHandler(w http.ResponseWriter, r *http.Request) {
	state, err := security.RandString(16)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
		return
	}
	nonce, err := security.RandString(16)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
		return
	}

	h.setCallbackCookie(w, r, "state", state)
	h.setCallbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, h.oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusSeeOther)
	logging.LogRequest(r.Method, r.URL.String(), http.StatusSeeOther)
}

func (h *OIDCHandler) callbackHandler(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusForbidden)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusForbidden)
		logging.LogError(err)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "Authentication failed", http.StatusForbidden)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusForbidden)
		return
	}

	oauth2Token, err := h.oauthConfig.Exchange(h.oidcContext, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(errors.New("error extracting id_token from oauth2 token"))
		return
	}

	idToken, err := h.oidcVerifier.Verify(h.oidcContext, rawIDToken)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusForbidden)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusForbidden)
		logging.LogError(err)
		return
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusForbidden)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusForbidden)
		logging.LogError(err)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "Authentication failed", http.StatusForbidden)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusForbidden)
		return
	}

	// Extract claims from idToken
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
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

	h.handleSAToken(w, r, groups, email)
	logging.LogRequest(r.Method, r.URL.String(), http.StatusSeeOther)
}
