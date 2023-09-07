package collect

import (
	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"gopkg.in/yaml.v2"
)

func GetNamespaceSeverityValues(yamlData []byte) (*v1beta1.ScopedConfigurationScanSummary, error) {
	var summary v1beta1.ScopedConfigurationScanSummary // Use the imported struct
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

func GetClusterSeverityValues(yamlData []byte) (*v1beta1.ScopedConfigurationScanSummaryList, error) {
	var summary v1beta1.ScopedConfigurationScanSummaryList // Use the imported struct
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}