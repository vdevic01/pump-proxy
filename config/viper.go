package config

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type ProxyConfigViper struct {
	JWTSecret               string              `cfg:"jwt_secret"`
	TargetURL               string              `cfg:"target_url"`
	EncryptionKey           string              `cfg:"encryption_key"`
	Port                    int16               `cfg:"port"`
	Host                    string              `cfg:"host"`
	TokenDuration           uint                `cfg:"token_duration"`
	ServiceAccountNamespace string              `cfg:"service_account_namespace"`
	Oidc                    *OidcOptionsViper   `cfg:"oidc"`
	Saml                    *SAMLOptionsViper   `cfg:"saml"`
	Cookie                  *CookieOptionsViper `cfg:"cookie"`
	Acl                     map[string]string   `cfg:"acl"`
	AuthType                string              `cfg:"auth_type"`
	RunInDebug              bool                `cfg:"run_in_debug"`
}

type OidcOptionsViper struct {
	OidcURL          string `cfg:"oidc_url"`
	OidcClientID     string `cfg:"oidc_client_id"`
	OidcClientSecret string `cfg:"oidc_client_secret"`
	OidcRedirectURL  string `cfg:"oidc_redirect_url"`
}

type CookieOptionsViper struct {
	Secure   bool   `cfg:"secure"`
	HttpOnly bool   `cfg:"http_only"`
	SameSite string `cfg:"same_site"`
}

type SAMLOptionsViper struct {
	IdpMetadataURL    string `cfg:"idp_metadata_url"`
	EntityID          string `cfg:"entity_id"`
	UserGroupAttrName string `cfg:"user_group_attr_name"`
	UserIDAttrName    string `cfg:"user_id_attr_name"`
	CertPath          string `cfg:"cert_path"`
	KeyPath           string `cfg:"key_path"`
}

func Load(configFileName string, into interface{}) error {
	v := viper.New()
	v.SetConfigFile(configFileName)
	v.SetConfigType("toml")
	v.SetEnvPrefix("PUMP_PROXY_APP")
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

	v.SetDefault("run_in_debug", false)

	if configFileName != "" {
		err := v.ReadInConfig()
		if err != nil {
			return fmt.Errorf("unable to load config file: %w", err)
		}
	}

	err := v.UnmarshalExact(into, viper.DecoderConfigOption(decodeFromCfgTag))
	if err != nil {
		return fmt.Errorf("error unmarshalling config: %w", err)
	}

	return nil
}

func decodeFromCfgTag(c *mapstructure.DecoderConfig) {
	c.TagName = "cfg"
}
