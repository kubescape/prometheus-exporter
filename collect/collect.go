package collect

import (
	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"gopkg.in/yaml.v2"
)

func GetSeverityValues(yamlData []byte, severity string) (int, error) {
	var summary v1beta1.WorkloadConfigurationScanSummary
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return 0, err
	}

	switch severity {
	case "critical":
		return summary.Spec.Severities.Critical, nil
	case "high":
		return summary.Spec.Severities.High, nil
	case "low":
		return summary.Spec.Severities.Low, nil
	case "medium":
		return summary.Spec.Severities.Medium, nil
	default:
		return summary.Spec.Severities.Unknown, nil
	}
}
