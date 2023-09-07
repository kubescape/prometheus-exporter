package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yrs147/kubescape-exporter/collect"
	"github.com/yrs147/kubescape-exporter/metrics"
)

func main() {

	ns, err := ioutil.ReadFile("test.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	nssummary, err := collect.GetNamespaceSeverityValues(ns)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	cluster, err := ioutil.ReadFile("cluster.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file : %v", err)
	}

	clustersummary, err := collect.GetClusterSeverityValues(cluster)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	metrics.ProcessClusterMetrics(clustersummary)
	metrics.ProcessNamespaceMetrics(nssummary)

	http.Handle("/metrics", promhttp.Handler())
	fmt.Println("Prometheus metrics server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
