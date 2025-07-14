package config

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type ProxyConfigViper struct {
	JWTSecret               string             `cfg:"jwt_secret"`
	TargetURL               string             `cfg:"target_url"`
	EncryptionKey           string             `cfg:"encryption_key"`
	Port                    int16              `cfg:"port"`
	Host                    string             `cfg:"host"`
	TokenDuration           uint               `cfg:"token_duration"`
	ServiceAccountNamespace string             `cfg:"service_account_namespace"`
	Oidc                    OidcOptionsViper   `cfg:"oidc"`
	Cookie                  CookieOptionsViper `cfg:"cookie"`
	GroupMapping            map[string]string  `cfg:"group_mapping"`
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

func NewProxyConfigViper() *ProxyConfigViper {
	return &ProxyConfigViper{
		JWTSecret:     "placeholder",
		TargetURL:     "https://placeholder.com",
		EncryptionKey: "11111111111111111111111111111111",
		Port:          8080,
		Host:          "localhost",
		TokenDuration: 3600,
		Oidc: OidcOptionsViper{
			OidcURL:          "https://login.microsoftonline.com/placeholder/v2.0",
			OidcClientID:     "placeholder",
			OidcClientSecret: "placeholder",
			OidcRedirectURL:  "http://localhost:8080/pumproxy/callback",
		},
		Cookie: CookieOptionsViper{
			Secure:   false,
			HttpOnly: true,
			SameSite: "Strict",
		},
		GroupMapping: map[string]string{
			"placeholder": "placeholder",
		},
	}
}

func Load(configFileName string, into interface{}) error {
	v := viper.New()
	v.SetConfigFile(configFileName)
	v.SetConfigType("toml")
	v.SetEnvPrefix("PUMP_PROXY")
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

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
