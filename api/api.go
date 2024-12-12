package api

import (
	"context"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/pager"
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
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").Watch(context.Background(), metav1.ListOptions{})
}

func (sc *StorageClientImpl) GetVulnerabilityManifestSummaries() (*v1beta1.VulnerabilityManifestSummaryList, error) {
	var list v1beta1.VulnerabilityManifestSummaryList
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").List(ctx, opts)
	}).EachListItem(context.TODO(), metav1.ListOptions{}, func(obj runtime.Object) error {
		// enrich the summary list with the full object as the list only contains the metadata
		summary := obj.(*v1beta1.VulnerabilityManifestSummary)
		item, err := sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries(summary.Namespace).Get(context.TODO(), summary.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		list.Items = append(list.Items, *item)
		return nil
	})

	return &list, err
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	vulnsummary, err := sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return vulnsummary, nil

}

func (sc *StorageClientImpl) WatchWorkloadConfigurationScanSummaries() (watch.Interface, error) {
	return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").Watch(context.Background(), metav1.ListOptions{})
}

func (sc *StorageClientImpl) GetWorkloadConfigurationScanSummaries() (*v1beta1.WorkloadConfigurationScanSummaryList, error) {
	var list v1beta1.WorkloadConfigurationScanSummaryList
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(ctx, opts)
	}).EachListItem(context.TODO(), metav1.ListOptions{}, func(obj runtime.Object) error {
		// enrich the summary list with the full object as the list only contains the metadata
		scan := obj.(*v1beta1.WorkloadConfigurationScanSummary)
		item, err := sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries(scan.Namespace).Get(context.TODO(), scan.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		list.Items = append(list.Items, *item)

		return nil
	})

	return &list, err
}

func (sc *StorageClientImpl) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	configscan, err := sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return configscan, nil

}
