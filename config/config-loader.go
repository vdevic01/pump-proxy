package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type ProxyConfigDto struct {
	JWTSecret               string            `cfg:"jwt_secret"`
	TargetURL               string            `cfg:"target_url"`
	EncryptionKey           string            `cfg:"encryption_key"`
	Port                    int16             `cfg:"port"`
	Host                    string            `cfg:"host"`
	TokenDuration           uint              `cfg:"token_duration"`
	ServiceAccountNamespace string            `cfg:"service_account_namespace"`
	Oidc                    *OidcOptionsDto   `cfg:"oidc"`
	Saml                    *SAMLOptionsDto   `cfg:"saml"`
	Cookie                  *CookieOptionsDto `cfg:"cookie"`
	Acl                     map[string]string `cfg:"acl"`
	AuthType                string            `cfg:"auth_type"`
	RunInDebug              bool              `cfg:"run_in_debug"`
}

type OidcOptionsDto struct {
	IdpURL       string `cfg:"idp_url"`
	ClientID     string `cfg:"client_id"`
	ClientSecret string `cfg:"client_secret"`
	RedirectURL  string `cfg:"redirect_url"`
}

type CookieOptionsDto struct {
	Secure   bool   `cfg:"secure"`
	HttpOnly bool   `cfg:"http_only"`
	SameSite string `cfg:"same_site"`
}

type SAMLOptionsDto struct {
	IdpMetadataURL    string `cfg:"idp_metadata_url"`
	EntityID          string `cfg:"entity_id"`
	UserGroupAttrName string `cfg:"user_group_attr_name"`
	UserIDAttrName    string `cfg:"user_id_attr_name"`
	CertPath          string `cfg:"cert_path"`
	KeyPath           string `cfg:"key_path"`
	RedirectURL       string `cfg:"redirect_url"`
}

func Load(configFileName string, into interface{}) error {
	k := koanf.New("")
	parser := toml.Parser()
	if err := k.Load(file.Provider(configFileName), parser); err != nil {
		return fmt.Errorf("unable to load config file: %w", err)
	}

	k.Load(env.Provider("/", env.Opt{
		Prefix: "PUMP_PROXY_APP_",
		TransformFunc: func(k, v string) (string, any) {
			k = strings.ToLower(strings.TrimPrefix(k, "PUMP_PROXY_APP_"))
			return k, v
		},
	}), nil)

	k.UnmarshalWithConf("", into, koanf.UnmarshalConf{Tag: "cfg"})

	return nil
}
