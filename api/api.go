package api

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type StorageClientImpl struct {
	clientset *spdxclient.Clientset
}

var _ StorageClient = &StorageClientImpl{}

func NewStorageClient() *StorageClientImpl {
	clusterConfig := k8sinterface.GetK8sConfig()
	if clusterConfig == nil {
		logger.L().Fatal("error getting cluster config")
	}
	// Create the dynamic client
	clientset, err := spdxclient.NewForConfig(clusterConfig)
	if err != nil {
		logger.L().Fatal("error creating dynamic client", helpers.Error(err))
	}
	return &StorageClientImpl{
		clientset: clientset,
	}
}

func (sc *StorageClientImpl) WatchVulnerabilityManifestSummaries() (watch.Interface, error) {
	// we need to pass the fullSpec resource version to get the full spec in Watch
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").Watch(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetVulnerabilityManifestSummaries() (*v1beta1.VulnerabilityManifestSummaryList, error) {
	// we need to pass the fullSpec resource version to get the full spec in GetList
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	// VulnerabilitySummaries is a virtual resource, it has to be enabled in the storage
	return sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) WatchWorkloadConfigurationScanSummaries() (watch.Interface, error) {
	// we need to pass the fullSpec resource version to get the full spec in Watch
	return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").Watch(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetWorkloadConfigurationScanSummaries() (*v1beta1.WorkloadConfigurationScanSummaryList, error) {
	// we need to pass the fullSpec resource version to get the full spec in GetList
	return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	// ConfigScanSummaries is a virtual resource, it has to be enabled in the storage
	return sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}
