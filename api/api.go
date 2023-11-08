package api

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

type StorageClientImpl struct {
	clientset *spdxclient.Clientset
}

var _ StorageClient = &StorageClientImpl{}

func NewStorageClient() *StorageClientImpl {
	return &StorageClientImpl{}
}

func (sc *StorageClientImpl) Initialize(kubeconfig string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return err
	}

	// Create the dynamic client
	clientset, err := spdxclient.NewForConfig(config)
	if err != nil {
		return err
	}

	sc.clientset = clientset
	return nil
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries(kubeconfig string) (*v1beta1.VulnerabilitySummaryList, error) {
	vulnsummary, err := sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return vulnsummary, nil

}

func (sc *StorageClientImpl) GetConfigScanSummaries(kubeconfig string) (*v1beta1.ConfigurationScanSummaryList, error) {
	configscan, err := sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return configscan, nil

}
