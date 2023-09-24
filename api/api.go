package api

import (
	"context"

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

func GetVulnerabilitySummary(kubeconfig string) ([]byte, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	// Create the dynamic client
	clientset, err := spdxclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Get the CRD object from the Kubernetes API server
	vulnsummary, err := clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	crd, err := yaml.Marshal(vulnsummary)
	if err != nil {
		return nil, err
	}

	return crd, nil

}

func GetConfigScanSummary(kubeconfig string) ([]byte, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	// Create the dynamic client
	clientset, err := spdxclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Get the CRD object from the Kubernetes API server
	configscan, err := clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	crd, err := yaml.Marshal(configscan)
	if err != nil {
		return nil, err
	}

	return crd, nil

}
