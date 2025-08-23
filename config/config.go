package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type AuthType string

const (
	AuthSAML AuthType = "saml"
	AuthOIDC AuthType = "oidc"
)

type ProxyConfig struct {
	JWTSecret               []byte
	TargetURL               *url.URL
	EncryptionKey           []byte // Must be 16, 32, or 64 bytes long
	Port                    int16
	Host                    string
	TokenDuration           time.Duration
	ServiceAccountNamespace string
	Oidc                    *OidcOptions
	Saml                    *SAMLOptions
	Cookie                  *CookieOptions
	Acl                     map[string]string // Maps OIDC groups to service accounts, each group can map to single service account
	AclSignature            string
	Auth                    AuthType
	RunInDebug              bool
}

type OidcOptions struct {
	IdpURL       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type CookieOptions struct {
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

type SAMLOptions struct {
	IdpMetadataURL    string
	EntityID          string
	UserGroupAttrName string // Can be a group or role of the user
	UserIDAttrName    string // Can be any attribute that uniquely identifies the user (e.g. email)
	CertPath          string // Path to the certificate file
	KeyPath           string // Path to the key file
}

func NewProxyConfig(configDto *ProxyConfigDto) (*ProxyConfig, error) {
	targetURL, err := url.Parse(configDto.TargetURL)
	if err != nil {
		return nil, err
	}

	sameSite, err := parseSameSite(configDto.Cookie.SameSite)
	if err != nil {
		return nil, err
	}

	auth, err := parseAuthType(configDto.AuthType)
	if err != nil {
		return nil, err
	}

	output := &ProxyConfig{
		JWTSecret:               []byte(configDto.JWTSecret),
		TargetURL:               targetURL,
		EncryptionKey:           []byte(configDto.EncryptionKey),
		Port:                    configDto.Port,
		Host:                    configDto.Host,
		ServiceAccountNamespace: configDto.ServiceAccountNamespace,
		TokenDuration:           time.Duration(configDto.TokenDuration) * time.Second,
		Cookie: &CookieOptions{
			Secure:   configDto.Cookie.Secure,
			HttpOnly: configDto.Cookie.HttpOnly,
			SameSite: sameSite,
		},
		Acl:          configDto.Acl,
		AclSignature: computeAclHash(configDto.Acl),
		Auth:         auth,
		RunInDebug:   configDto.RunInDebug,
	}
	if auth == AuthSAML {
		output.Saml = &SAMLOptions{
			IdpMetadataURL:    configDto.Saml.IdpMetadataURL,
			EntityID:          configDto.Saml.EntityID,
			UserGroupAttrName: configDto.Saml.UserGroupAttrName,
			UserIDAttrName:    configDto.Saml.UserIDAttrName,
			CertPath:          configDto.Saml.CertPath,
			KeyPath:           configDto.Saml.KeyPath,
		}
	} else {
		output.Oidc = &OidcOptions{
			IdpURL:       configDto.Oidc.IdpURL,
			ClientID:     configDto.Oidc.ClientID,
			ClientSecret: configDto.Oidc.ClientSecret,
			RedirectURL:  configDto.Oidc.RedirectURL,
		}
	}

	return output, nil
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

func parseAuthType(auth string) (AuthType, error) {
	switch auth {
	case string(AuthSAML):
		return AuthSAML, nil
	case string(AuthOIDC):
		return AuthOIDC, nil
	default:
		return "", fmt.Errorf("invalid AuthType: %s", auth)
	}
}

func computeAclHash(acl map[string]string) string {
	keys := make([]string, 0, len(acl))
	for k := range acl {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	data := ""
	for _, k := range keys {
		data += k + "=" + acl[k] + ";"
	}

	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
