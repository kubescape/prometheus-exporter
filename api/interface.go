package api

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

type StorageClient interface {
	GetVulnerabilitySummaries(kubeconfig string) (*v1beta1.VulnerabilitySummaryList, error)
	GetConfigScanSummaries(kubeconfig string) (*v1beta1.ConfigurationScanSummaryList, error)
	Initialize(kubeconfig string) error
}
