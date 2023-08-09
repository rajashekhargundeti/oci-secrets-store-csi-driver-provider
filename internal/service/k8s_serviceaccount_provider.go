/*
** OCI Secrets Store CSI Driver Provider
**
** Copyright (c) 2022 Oracle America, Inc. and its affiliates.
** Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 */
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oracle-samples/oci-secrets-store-csi-driver-provider/internal/types"
	"github.com/rs/zerolog/log"
	authenticationv1 "k8s.io/api/authentication/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const tokenRequestAudience = "oci"

type K8sServiceAccountTokenProvider struct {
	types.PodInfo
}

func NewK8sServiceAccountTokenProvider(podInfo types.PodInfo) K8sServiceAccountTokenProvider {
	return K8sServiceAccountTokenProvider{
		PodInfo: podInfo,
	}
}

// ServiceAccountToken returns a service account token
func (d K8sServiceAccountTokenProvider) ServiceAccountToken() (string, error) {
	podInfo := d.PodInfo
	saTokenStr, err := getSAToken(podInfo)
	if err != nil {
		err := fmt.Errorf("can not get or generate token for service account: %s, namespace: %s, Error: %v",
			podInfo.ServiceAccountName, podInfo.Namespace, err)
		return "", err
	}
	return saTokenStr, nil
}

func getSAToken(podInfo types.PodInfo) (string, error) {
	// Obtain a serviceaccount token for the pod.
	var saTokenVal string
	if podInfo.ServiceAccountTokens != "" {
		log.Info().Msg("Using service account token from the request")
		saToken, err := extractSAToken(podInfo.ServiceAccountTokens) // calling function to extract token received from driver.
		if err != nil {
			return "", fmt.Errorf("unable to fetch SA token from driver: %w", err)
		}
		saTokenVal = saToken.Token
	} else {
		log.Info().Msg("Generating service account token using token request api")
		saToken, err := generatePodSAToken(podInfo) // if no token received, provider generates its own token.
		if err != nil {
			return "", fmt.Errorf("unable to fetch pod token: %w", err)
		}
		saTokenVal = saToken.Token
	}
	return saTokenVal, nil
}

func extractSAToken(saTokens string) (*authenticationv1.TokenRequestStatus, error) {
	audienceTokens := map[string]authenticationv1.TokenRequestStatus{}
	if err := json.Unmarshal([]byte(saTokens), &audienceTokens); err != nil {
		return nil, err
	}

	for k, v := range audienceTokens {
		if k == tokenRequestAudience { // Only returns the token if the audience is the workload identity. Other tokens cannot be used.
			return &v, nil
		}
	}
	return nil, fmt.Errorf("no token has audience value of %s", tokenRequestAudience)
}

func getK8sClientSet() (*kubernetes.Clientset, error) {
	clusterCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("can not get cluster config. error: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("can not initialize kubernetes client. error: %v", err)
	}

	return clientset, nil
}

func generatePodSAToken(podInfo types.PodInfo) (*authenticationv1.TokenRequestStatus, error) {
	clientSet, err := getK8sClientSet()
	if err != nil {
		return nil, fmt.Errorf("unable to get k8s client: %v", err)
	}
	ttl := int64((15 * time.Minute).Seconds())
	resp, err := clientSet.CoreV1().
		ServiceAccounts(podInfo.Namespace).
		CreateToken(context.Background(), podInfo.ServiceAccountName,
			&authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					ExpirationSeconds: &ttl,
					Audiences:         []string{tokenRequestAudience},
					BoundObjectRef: &authenticationv1.BoundObjectReference{
						Kind:       "Pod",
						APIVersion: "v1",
						Name:       podInfo.Name,
						UID:        podInfo.UID,
					},
				},
			},
			meta.CreateOptions{},
		)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch token from token api: %v", err)
	}
	// fmt.Printf("\nToken Response: %v", resp)
	// fmt.Printf("\nToken: %v", resp.Status.Token)
	return &resp.Status, nil
}
