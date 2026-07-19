package cluster

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

type ProviderSecretStore struct {
	client kubernetes.Interface
}

func NewProviderSecretStore() (*ProviderSecretStore, error) {
	config, err := kubeConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &ProviderSecretStore{client: client}, nil
}

func (s *ProviderSecretStore) Upsert(ctx context.Context, namespace, name, key string, value []byte) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("Kubernetes client is not configured")
	}
	if problems := validation.IsDNS1123Label(namespace); len(problems) > 0 {
		return fmt.Errorf("invalid secret namespace: %s", problems[0])
	}
	if problems := validation.IsDNS1123Subdomain(name); len(problems) > 0 {
		return fmt.Errorf("invalid secret name: %s", problems[0])
	}
	if problems := validation.IsConfigMapKey(key); len(problems) > 0 {
		return fmt.Errorf("invalid secret key: %s", problems[0])
	}
	if len(value) == 0 {
		return fmt.Errorf("secret value is required")
	}
	secrets := s.client.CoreV1().Secrets(namespace)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := secrets.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = secrets.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Type:       corev1.SecretTypeOpaque,
				Data:       map[string][]byte{key: append([]byte(nil), value...)},
			}, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}
		current = current.DeepCopy()
		if current.Data == nil {
			current.Data = map[string][]byte{}
		}
		current.Data[key] = append([]byte(nil), value...)
		_, err = secrets.Update(ctx, current, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("upsert Kubernetes Secret %s/%s: %w", namespace, name, err)
	}
	return nil
}
