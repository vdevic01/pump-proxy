package config

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProxyConfig struct {
	JWTSecret               []byte
	TargetURL               *url.URL
	EncryptionKey           []byte // Must be 16, 32, or 64 bytes long
	Port                    int16
	Host                    string
	TokenDuration           time.Duration
	ServiceAccountNamespace string
	Oidc                    OidcOptions
	Cookie                  CookieOptions
	GroupMapping            map[string]string // Maps OIDC groups to service accounts, each group can map to single service account
}

type OidcOptions struct {
	OidcURL          string
	OidcClientID     string
	OidcClientSecret string
	OidcRedirectURL  string
}

type CookieOptions struct {
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

func NewProxyConfig(viperConfig *ProxyConfigViper) (*ProxyConfig, error) {
	targetURL, err := url.Parse(viperConfig.TargetURL)
	if err != nil {
		return nil, err
	}

	sameSite, err := parseSameSite(viperConfig.Cookie.SameSite)
	if err != nil {
		return nil, err
	}

	return &ProxyConfig{
		JWTSecret:               []byte(viperConfig.JWTSecret),
		TargetURL:               targetURL,
		EncryptionKey:           []byte(viperConfig.EncryptionKey),
		Port:                    viperConfig.Port,
		Host:                    viperConfig.Host,
		ServiceAccountNamespace: viperConfig.ServiceAccountNamespace,
		TokenDuration:           time.Duration(viperConfig.TokenDuration) * time.Second,
		Oidc: OidcOptions{
			OidcURL:          viperConfig.Oidc.OidcURL,
			OidcClientID:     viperConfig.Oidc.OidcClientID,
			OidcClientSecret: viperConfig.Oidc.OidcClientSecret,
			OidcRedirectURL:  viperConfig.Oidc.OidcRedirectURL,
		},
		Cookie: CookieOptions{
			Secure:   viperConfig.Cookie.Secure,
			HttpOnly: viperConfig.Cookie.HttpOnly,
			SameSite: sameSite,
		},
		GroupMapping: viperConfig.GroupMapping,
	}, nil
}

func parseSameSite(mode string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	case "":
		return http.SameSiteDefaultMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("invalid SameSite value: %s", mode)
	}
}
