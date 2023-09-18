package collect

import (
	"gopkg.in/yaml.v2"
	vuln "github.com/kubescape/storage/pkg/apis/softwarecomposition"
	
)

func GetVulnerabilityNamespaceSeverityValues(yamlData []byte) (*vuln.VulnerabilitySummary, error){
	var summary vuln.VulnerabilitySummary
	if err := yaml.Unmarshal(yamlData, &summary); err!=nil{
		return nil,err
	}
	return &summary, nil
}

func GetVulnerabilityClusterSeverityValues(yamlData []byte) (*vuln.VulnerabilitySummaryList, error){
	var summary vuln.VulnerabilitySummaryList
	if err := yaml.Unmarshal(yamlData, &summary); err!=nil{
		return nil,err
	}
	return &summary, nil
}

func GetConfigscanNamespaceSeverityValues(yamlData []byte) (*vuln.ConfigurationScanSummary, error) {
	var summary vuln.ConfigurationScanSummary 
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

func GetConfigscanClusterSeverityValues(yamlData []byte) (*vuln.ConfigurationScanSummaryList, error) {
	var summary vuln.ConfigurationScanSummaryList 
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}