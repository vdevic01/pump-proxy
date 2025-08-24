package handlers

import (
	"PumpProxy/config"
	"PumpProxy/logging"
	saservice "PumpProxy/services/sa-service"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
)

type SAMLHandler struct {
	SAHandler
	middleware *samlsp.Middleware
	saService  *saservice.SAService
	config     *config.ProxyConfig
}

func NewSAMLHandler(prefix string, config *config.ProxyConfig, saService *saservice.SAService) *SAMLHandler {
	keyPair, err := tls.LoadX509KeyPair(config.Saml.CertPath, config.Saml.KeyPath)
	if err != nil {
		log.Fatal("Failed to load key pair:", err)
	}
	keyPair.Leaf, _ = x509.ParseCertificate(keyPair.Certificate[0])

	samlContext := context.Background()
	idpMetadataURL, _ := url.Parse(config.Saml.IdpMetadataURL)
	idpMetadata, err := samlsp.FetchMetadata(samlContext, http.DefaultClient, *idpMetadataURL)
	if err != nil {
		log.Fatal("Failed to load IdP metadata:", err)
	}

	rootURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", config.Port))

	middleware, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		AllowIDPInitiated: true,
		IDPMetadata:       idpMetadata,
		EntityID:          config.Saml.EntityID,
	})

	if err != nil {
		log.Fatal("Failed to create SAML middleware:", err)
	}

	return &SAMLHandler{
		SAHandler:  *NewSAHandler(prefix, saService),
		middleware: middleware,
		saService:  saService,
		config:     config,
	}
}

func (h *SAMLHandler) RegisterEndpoints() {
	http.Handle(h.prefix+"/auth", h.middleware.RequireAccount(http.HandlerFunc(h.authHandler)))
	http.Handle("/saml/", h.middleware)
}

func (h *SAMLHandler) authHandler(w http.ResponseWriter, r *http.Request) {
	samlSession := samlsp.SessionFromContext(r.Context())

	if samlSession == nil {
		http.Error(w, "no SAML session found", http.StatusUnauthorized)
		return
	}

	customSession, ok := samlSession.(samlsp.SessionWithAttributes)
	if !ok {
		http.Error(w, "invalid SAML session type", http.StatusUnauthorized)
		return
	}

	groups := customSession.GetAttributes()[h.config.Saml.UserGroupAttrName]
	email := customSession.GetAttributes()[h.config.Saml.UserIDAttrName][0]

	h.handleSAToken(w, r, groups, email)
	logging.LogRequest(r.Method, r.URL.String(), http.StatusSeeOther)
}
