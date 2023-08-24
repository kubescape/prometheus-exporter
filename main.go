package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

type Severities struct {
	Critical    Severity `yaml:"critical"`
	High        Severity `yaml:"high"`
	Low         Severity `yaml:"low"`
	Medium      Severity `yaml:"medium"`
	Negligible  Severity `yaml:"negligible"`
	Unknown     Severity `yaml:"unknown"`
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

func main() {
	// Read the YAML file
	yamlFile, err := ioutil.ReadFile("vulnerability-mock.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	// Unmarshal the YAML data into the struct
	var summary VulnerabilitySummary
	if err := yaml.Unmarshal(yamlFile, &summary); err != nil {
		log.Fatalf("Error unmarshaling YAML: %v", err)
	}

	// Print the values of the severities
	fmt.Printf("Critical (all): %d\n", summary.Spec.Severities.Critical.All)
	fmt.Printf("Critical (relevant): %d\n", summary.Spec.Severities.Critical.Relevant)
	fmt.Printf("High (all): %d\n", summary.Spec.Severities.High.All)
	fmt.Printf("High (relevant): %d\n", summary.Spec.Severities.High.Relevant)
	fmt.Printf("Medium (all): %d\n", summary.Spec.Severities.Medium.All)
	fmt.Printf("Medium (relevant): %d\n", summary.Spec.Severities.Medium.Relevant)
	fmt.Printf("Low (all): %d\n", summary.Spec.Severities.Low.All)
	fmt.Printf("Low (relevant): %d\n", summary.Spec.Severities.Low.Relevant)
	fmt.Printf("Negligible (all): %d\n", summary.Spec.Severities.Negligible.All)
	fmt.Printf("Negligible (relevant): %d\n", summary.Spec.Severities.Negligible.Relevant)
}
