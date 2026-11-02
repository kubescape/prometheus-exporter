package api

import (
	"context"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type StorageClient interface {
	GetVulnerabilitySummaries(context.Context) (*v1beta1.VulnerabilitySummaryList, error)
	GetConfigScanSummaries(context.Context) (*v1beta1.ConfigurationScanSummaryList, error)
}
