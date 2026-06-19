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

// pagedList is satisfied by the *...List pointer types generated for the
// softwarecomposition API. The continue accessors are promoted from the
// embedded metav1.ListMeta.
type pagedList[T any] interface {
	*T
	GetContinue() string
	SetContinue(string)
}

// listAllPages lists every page of a resource, following the continuation token
// the storage backend returns, and concatenates the items into a single list.
//
// The storage backend (kubescape/storage) applies a default page size of 500
// when a client lists without an explicit limit and returns a continue token
// for the remaining objects. A consumer that ignores that token silently sees
// only the first 500 objects, which produces wrong cluster-wide and
// per-namespace metrics on larger clusters (kubescape/storage#337). Following
// the token guarantees the aggregation covers every object.
//
// ResourceVersionFullSpec is preserved across pages so every page carries the
// full object spec rather than metadata only; it is set on ResourceVersion
// (not ResourceVersionMatch), which is the only field allowed alongside a
// continue token.
func listAllPages[T any, PT pagedList[T]](
	list func(opts metav1.ListOptions) (PT, error),
	appendItems func(dst, src PT),
) (PT, error) {
	opts := metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec}
	var all PT
	for {
		page, err := list(opts)
		if err != nil {
			return nil, err
		}
		if all == nil {
			all = page
		} else {
			appendItems(all, page)
		}
		token := page.GetContinue()
		if token == "" {
			// The accumulated list is complete; drop the first page's token so
			// callers don't mistake it for a truncated result.
			all.SetContinue("")
			return all, nil
		}
		opts.Continue = token
	}
}

func (sc *StorageClientImpl) WatchVulnerabilityManifestSummaries() (watch.Interface, error) {
	// we need to pass the fullSpec resource version to get the full spec in Watch
	return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").Watch(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetVulnerabilityManifestSummaries() (*v1beta1.VulnerabilityManifestSummaryList, error) {
	// we need to pass the fullSpec resource version to get the full spec in GetList
	return listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
			return sc.clientset.SpdxV1beta1().VulnerabilityManifestSummaries("").List(context.Background(), opts)
		},
		func(dst, src *v1beta1.VulnerabilityManifestSummaryList) {
			dst.Items = append(dst.Items, src.Items...)
		},
	)
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	// VulnerabilitySummaries is a virtual resource, it has to be enabled in the storage
	return listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.VulnerabilitySummaryList, error) {
			return sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.Background(), opts)
		},
		func(dst, src *v1beta1.VulnerabilitySummaryList) {
			dst.Items = append(dst.Items, src.Items...)
		},
	)
}

func (sc *StorageClientImpl) WatchWorkloadConfigurationScanSummaries() (watch.Interface, error) {
	// we need to pass the fullSpec resource version to get the full spec in Watch
	return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").Watch(context.Background(), metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec})
}

func (sc *StorageClientImpl) GetWorkloadConfigurationScanSummaries() (*v1beta1.WorkloadConfigurationScanSummaryList, error) {
	// we need to pass the fullSpec resource version to get the full spec in GetList
	return listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.WorkloadConfigurationScanSummaryList, error) {
			return sc.clientset.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(context.Background(), opts)
		},
		func(dst, src *v1beta1.WorkloadConfigurationScanSummaryList) {
			dst.Items = append(dst.Items, src.Items...)
		},
	)
}

func (sc *StorageClientImpl) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	// ConfigScanSummaries is a virtual resource, it has to be enabled in the storage
	return listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.ConfigurationScanSummaryList, error) {
			return sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.Background(), opts)
		},
		func(dst, src *v1beta1.ConfigurationScanSummaryList) {
			dst.Items = append(dst.Items, src.Items...)
		},
	)
}
