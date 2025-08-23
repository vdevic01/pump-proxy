package handlers

import (
	"PumpProxy/config"
	"PumpProxy/file-system/templates"
	"PumpProxy/logging"
	"PumpProxy/security"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ProxyHandler struct {
	BaseHandler
	proxy         httputil.ReverseProxy
	proxyConfig   *config.ProxyConfig
	jwtSecret     []byte
	encryptionKey []byte
}

func NewProxyHandler(prefix string, config *config.ProxyConfig) *ProxyHandler {
	return &ProxyHandler{
		BaseHandler:   BaseHandler{prefix: prefix},
		proxyConfig:   config,
		proxy:         *httputil.NewSingleHostReverseProxy(config.TargetURL),
		jwtSecret:     config.JWTSecret,
		encryptionKey: config.EncryptionKey,
	}
}

func (h *ProxyHandler) RegisterEndpoints() {
	http.Handle(h.prefix+"/", http.HandlerFunc(h.defaultHandler))
	http.Handle(h.prefix+"/robots.txt", http.HandlerFunc(h.robotsHandler))
	http.Handle(h.prefix+"/.well-known/", http.HandlerFunc(h.wellKnownHandler))
}

func (h *ProxyHandler) robotsHandler(w http.ResponseWriter, r *http.Request) {
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func (h *ProxyHandler) wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	logging.LogRequest(r.Method, r.URL.String(), http.StatusNotFound)
	http.Error(w, "Not Found", http.StatusNotFound)
}

func (h *ProxyHandler) defaultHandler(w http.ResponseWriter, r *http.Request) {
	if !h.isValidRequest(r) {
		page, err := templates.ReadSigninPage()
		if err != nil {
			logging.LogRequest(r.Method, r.URL.String(), http.StatusInternalServerError)
			logging.LogError(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(page)
		logging.LogRequest(r.Method, r.URL.String(), http.StatusUnauthorized)
		return
	}
	logging.LogRequest(r.Method, r.URL.String(), http.StatusOK)
	h.proxy.ServeHTTP(w, r)
}

func (h *ProxyHandler) isValidRequest(r *http.Request) bool {
	authToken, err := h.readTokenFromCookies(r)
	if err != nil {
		logging.LogError(err)
		return false
	}
	parsedAuthToken, err := h.parseToken(authToken)
	if err != nil {
		logging.LogError(err)
		return false
	}
	claims, ok := parsedAuthToken.Claims.(jwt.MapClaims)
	if !ok {
		logging.LogError(errors.New("error parsing jwt claims"))
		return false
	}
	if !h.isTokenValid(claims) {
		return false
	}
	saToken, err := h.extractServiceAccountToken(claims)
	if err != nil {
		logging.LogError(err)
		return false
	}
	r.Header.Set("Authorization", "Bearer "+saToken)
	return true
}

func (h *ProxyHandler) readTokenFromCookies(req *http.Request) (string, error) {
	cookie, err := req.Cookie("token")
	if err != nil {
		return "", fmt.Errorf("token cookie not found: %w", err)
	}
	return cookie.Value, nil
}

func (h *ProxyHandler) parseToken(token string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return h.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, errors.New("token is invalid")
	}

	return parsedToken, nil
}

func (h *ProxyHandler) isTokenExpired(claims jwt.MapClaims) bool {
	if exp, ok := claims["exp"].(float64); ok {
		return int64(exp) < (time.Now().Unix())
	}
	return true
}

func (h *ProxyHandler) isAclSignatureValid(claims jwt.MapClaims) bool {
	return claims["acl_signature"] == h.proxyConfig.AclSignature
}

func (h *ProxyHandler) isTokenValid(claims jwt.MapClaims) bool {
	return !h.isTokenExpired(claims) && h.isAclSignatureValid(claims)
}

func (h *ProxyHandler) extractServiceAccountToken(claims jwt.MapClaims) (string, error) {
	encodedToken, ok := claims["service_account_token"].(string)
	if !ok {
		return "", errors.New("service account token not found in claims")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode service account token: %w", err)
	}

	decryptedToken, err := security.Decrypt(decodedToken, h.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt service account token: %w", err)
	}
	return decryptedToken, nil
}
