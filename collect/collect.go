package collect

import (
	"gopkg.in/yaml.v2"
	sc "github.com/kubescape/storage/pkg/apis/softwarecomposition"
	
)

func GetVulnerabilitySeverityValues(yamlData []byte) (*sc.VulnerabilitySummaryList, error){
	var summary sc.VulnerabilitySummaryList
	if err := yaml.Unmarshal(yamlData, &summary); err!=nil{
		return nil,err
	}
	return &summary, nil
}


func GetConfigscanSeverityValues(yamlData []byte) (*sc.ConfigurationScanSummaryList, error) {
	var summary sc.ConfigurationScanSummaryList 
	if err := yaml.Unmarshal(yamlData, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}
