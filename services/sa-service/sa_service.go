package saservice

import (
	"PumpProxy/config"
	"PumpProxy/kube"
	"PumpProxy/security"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type SAService struct {
	config     *config.ProxyConfig
	kubeClient *kube.KubeClient
}

func NewSAService(config *config.ProxyConfig, kubeClient *kube.KubeClient) *SAService {
	return &SAService{
		config:     config,
		kubeClient: kubeClient,
	}
}

func (service *SAService) AcquireSAToken(groups []string, email string) (string, string, error) {
	saName, err := service.getSAName(groups, email)
	if err != nil {
		return "", "", err
	}

	saToken, err := service.getSAToken(saName)
	if err != nil {
		return "", "", err
	}

	securedToken, err := service.secureSAToken(saToken)
	if err != nil {
		return "", "", err
	}

	return securedToken, saName, nil
}

func (service *SAService) getSAName(groups []string, email string) (string, error) {
	// In the future email may be used in access control logic, currently only groups are used
	serviceAccountName := ""

	for _, k := range groups {
		if val, ok := service.config.Acl[k]; ok {
			serviceAccountName = val
			break
		}
	}

	if serviceAccountName == "" {
		return "", &SAServiceForbiddenError{
			Msg: fmt.Sprintf("no service account corresponds to %v user groups or %s email", groups, email),
		}
	}
	return serviceAccountName, nil
}

func (service *SAService) getSAToken(serviceAccountName string) (string, error) {
	if service.config.RunInDebug {
		return "placeholder-token", nil
	} else {
		tokenDuration := int64(service.config.TokenDuration.Seconds())
		token, err := service.kubeClient.GenerateServiceAccountToken(serviceAccountName, service.config.ServiceAccountNamespace, tokenDuration)
		if err != nil {
			return "", &SAServiceInternalError{
				Msg: fmt.Sprintf("failed to generate service account token for %s: %v", serviceAccountName, err),
				Err: err,
			}
		}
		return token, nil
	}
}

func (service *SAService) secureSAToken(token string) (string, error) {
	encryptedToken, err := security.Encrypt([]byte(token), service.config.EncryptionKey)
	if err != nil {
		return "", &SAServiceInternalError{
			Msg: fmt.Sprintf("failed to encrypt service account token: %v", err),
			Err: err,
		}
	}
	encodedToken := base64.StdEncoding.EncodeToString(encryptedToken)
	return encodedToken, nil
}

func (service *SAService) GenerateSATokenCookie(saToken string) (*http.Cookie, error) {
	claims := jwt.MapClaims{
		"iss":                   "pump-proxy",
		"exp":                   time.Now().Add(service.config.TokenDuration).Unix(),
		"service_account_token": saToken,
		"acl_signature":         service.config.AclSignature,
	}
	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedAuthToken, err := authToken.SignedString(service.config.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("error occurred while signing jwt: %w", err)
	}
	return &http.Cookie{
		Name:     "token",
		Value:    signedAuthToken,
		Path:     "/",
		HttpOnly: service.config.Cookie.HttpOnly,
		Secure:   service.config.Cookie.Secure,
		SameSite: service.config.Cookie.SameSite,
		Expires:  time.Now().Add(service.config.TokenDuration),
	}, nil
}
