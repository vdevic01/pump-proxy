package handlers

import (
	"PumpProxy/config"
	"PumpProxy/logging"
	"PumpProxy/templates"
	"net/http"
)

type AuthPageHandler struct {
	BaseHandler
	proxyConfig *config.ProxyConfig
}

func NewAuthPageHandler(prefix string, config *config.ProxyConfig) *AuthPageHandler {
	return &AuthPageHandler{
		BaseHandler: BaseHandler{prefix: prefix},
		proxyConfig: config,
	}
}

func (h *AuthPageHandler) RegisterEndpoints() {
	http.Handle(h.prefix+"/sign_in", http.HandlerFunc(h.signInHandler))
	http.Handle(h.prefix+"/sign_out", http.HandlerFunc(h.signOutHandler))
}

func (h *AuthPageHandler) signInHandler(w http.ResponseWriter, r *http.Request) {
	page, err := templates.ReadSigninPage()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
		return
	}
	w.Write(page)
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
}

func (h *AuthPageHandler) signOutHandler(w http.ResponseWriter, r *http.Request) {
	page, err := templates.ReadSigninPage()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
		logging.LogError(err)
		return
	}
	h.deleteCookies(w, r)
	w.Write(page)
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
}
