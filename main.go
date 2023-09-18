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

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Prometheus metrics server started on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()
	
	//To Monitor the severities in objects
	for {
	ns, err := ioutil.ReadFile("namespace.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	nssummary, err := collect.GetConfigscanNamespaceSeverityValues(ns)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	cluster, err := ioutil.ReadFile("cluster.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file : %v", err)
	}

	clustersummary, err := collect.GetConfigscanClusterSeverityValues(cluster)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	vulnns, err := ioutil.ReadFile("vuln-ns.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file : %v", err)
	}

	vulnnssummary, err := collect.GetVulnerabilityNamespaceSeverityValues(vulnns)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	vulnclus, err := ioutil.ReadFile("vuln-cluster.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file : %v", err)
	}

	vulnclustersummary, err := collect.GetVulnerabilityClusterSeverityValues(vulnclus)
	if err != nil {
		fmt.Println("Error parsing YAML : ", err)
		os.Exit(1)
	}

	metrics.ProcessVulnNamespaceMetrics(vulnnssummary)
	metrics.ProcessVulnClusterMetrics(vulnclustersummary)

	metrics.ProcessConfigscanClusterMetrics(clustersummary)
	metrics.ProcessConfigscanNamespaceMetrics(nssummary)

	}

}