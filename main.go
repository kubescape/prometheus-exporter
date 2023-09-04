package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yrs147/kubescape-exporter/collect"
)

func main() {

	yamlData, err := ioutil.ReadFile("test.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	summary, err := collect.GetSeverityValues(yamlData)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	collect.ProcessMetrics(summary)

	http.Handle("/metrics", promhttp.Handler())
	fmt.Println("Prometheus metrics server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
