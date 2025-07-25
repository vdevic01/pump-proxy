package kube

import (
	"PumpProxy/config"
	"context"
	"fmt"

	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubeClient struct {
	clientset *kubernetes.Clientset
}

func NewKubeClient(proxyConfig *config.ProxyConfig) *KubeClient {
	if proxyConfig.RunInDebug {
		return &KubeClient{
			clientset: nil,
		}
	} else {
		kubeConfig, err := rest.InClusterConfig()
		if err != nil {
			panic(fmt.Errorf("failed to get in-cluster config: %w", err))
		}

		clientset, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			panic(fmt.Errorf("failed to create clientset: %w", err))
		}

		return &KubeClient{
			clientset: clientset,
		}
	}
}

func (client *KubeClient) GenerateServiceAccountToken(serviceAccountName string, namespace string, duration int64) (string, error) {
	tr := &v1.TokenRequest{
		Spec: v1.TokenRequestSpec{
			Audiences:         []string{"api"},
			ExpirationSeconds: &duration,
		},
	}

	tokenRequest, err := client.clientset.CoreV1().ServiceAccounts(namespace).CreateToken(context.TODO(), serviceAccountName, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	return tokenRequest.Status.Token, nil
}
