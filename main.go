package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/yrs147/kubescape-exporter/collect"
)

func main() {
	yamlData, err := ioutil.ReadFile("vulnerability-mock.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	criticalAll, criticalRelevant, err := collect.GetSeverityValues(yamlData, "high")
	if err != nil {
		log.Fatalf("Error getting high severity values: %v", err)
	}

	fmt.Printf("High (all): %d\n", criticalAll)
	fmt.Printf("High (relevant): %d\n", criticalRelevant)
}
