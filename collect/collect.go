package collect

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

type Severities struct {
	Critical   Severity `yaml:"critical"`
	High       Severity `yaml:"high"`
	Low        Severity `yaml:"low"`
	Medium     Severity `yaml:"medium"`
	Negligible Severity `yaml:"negligible"`
	Unknown    Severity `yaml:"unknown"`
}

type Severity struct {
	All      int `yaml:"all"`
	Relevant int `yaml:"relevant"`
}
type Spec struct {
	Severities Severities `yaml:"severities"`
}
type VulnerabilitySummary struct {
	Spec Spec `yaml:"spec"`
}

func GetSeverityValues(yamlData []byte, severity string) (int, int, error) {
	var summary VulnerabilitySummary
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return 0, 0, err
	}

	switch severity {
	case "critical":
		return summary.Spec.Severities.Critical.All, summary.Spec.Severities.Critical.Relevant, nil
	case "high":
		return summary.Spec.Severities.High.All, summary.Spec.Severities.High.Relevant, nil
	case "low":
		return summary.Spec.Severities.Low.All, summary.Spec.Severities.Low.Relevant, nil
	case "medium":
		return summary.Spec.Severities.Medium.All, summary.Spec.Severities.Medium.Relevant, nil
	case "negligible":
		return summary.Spec.Severities.Negligible.All, summary.Spec.Severities.Negligible.Relevant, nil
	default:
		return 0, 0, fmt.Errorf("unknown severity: %s", severity)
	}
}
