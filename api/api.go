package api

import (
	"context"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
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

func (sc *StorageClientImpl) GetVulnerabilityManifestSummaries() (*v1beta1.VulnerabilityManifestSummaryList, error) {
	vulnerabilityManifestSummaries, err := sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// TODO check if there's a better way instead of looping through all the items which is not efficient (time and memory)
	// enrich the summary list with the full object as the list only contains the metadata
	var list v1beta1.VulnerabilityManifestSummaryList
	for _, vuln := range vulnerabilityManifestSummaries.Items {
		item, err := sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries(vuln.Namespace).Get(context.TODO(), vuln.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		list.Items = append(list.Items, *item)
	}

	return &list, nil
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	vulnsummary, err := sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return vulnsummary, nil

}

func (sc *StorageClientImpl) GetWorkloadConfigurationScanSummaries() (*v1beta1.WorkloadConfigurationScanSummaryList, error) {
	workloadConfigurationScanSummaries, err := sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// TODO check if there's a better way instead of looping through all the items which is not efficient (time and memory)
	// enrich the summary list with the full object as the list only contains the metadata
	var list v1beta1.WorkloadConfigurationScanSummaryList
	for _, scan := range workloadConfigurationScanSummaries.Items {
		item, err := sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries(scan.Namespace).Get(context.TODO(), scan.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		list.Items = append(list.Items, *item)
	}

	return &list, nil
}

func (sc *StorageClientImpl) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	configscan, err := sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return configscan, nil

}
