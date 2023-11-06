package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yrs147/kubescape-exporter/api"
	"github.com/yrs147/kubescape-exporter/collect"
	"github.com/yrs147/kubescape-exporter/metrics"
)

func main() {

	kubeconfig := flag.String("kubeconfig", "KUBECONFIG", "location of kubeconfig")
	flag.Parse()

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Prometheus metrics server started on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	//To Monitor the severities in objects
	for {
		ns, err := api.GetConfigScanSummary(*kubeconfig)
		if err != nil {
			log.Fatalf("Error parsing YAML file: %v", err)
		}

		nssummary, err := collect.GetConfigscanSeverityValues(ns)
		if err != nil {
			fmt.Println("Error parsing YAML file: ", err)
			os.Exit(1)
		}

		cluster, err := api.GetConfigScanSummary(*kubeconfig)
		if err != nil {
			log.Fatalf("Error parsing YAML file : %v", err)
		}

		clustersummary, err := collect.GetConfigscanSeverityValues(cluster)
		if err != nil {
			fmt.Println("Error parsing YAML file: ", err)
			os.Exit(1)
		}

		vulnns, err := api.GetVulnerabilitySummary(*kubeconfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting CRD as YAML: %v\n", err)
			os.Exit(1)
		}
		vulnnssummary, err := collect.GetVulnerabilitySeverityValues(vulnns)
		if err != nil {
			fmt.Println("Error parsing YAML : ", err)
			os.Exit(1)
		}

		vulnclus, err := api.GetVulnerabilitySummary(*kubeconfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting CRD as YAML: %v\n", err)
			os.Exit(1)
		}

		vulnclustersummary, err := collect.GetVulnerabilitySeverityValues(vulnclus)
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
