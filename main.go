package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/prometheus-exporter/api"
	"github.com/kubescape/prometheus-exporter/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	var storageClient api.StorageClient
	storageClient = api.NewStorageClient()

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Prometheus metrics server started on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// monitor the severities in objects
	for {

		configScanSummaries, err := storageClient.GetConfigScanSummaries()
		if err != nil {
			logger.L().Error("error getting configuration scan summaries", helpers.Error(err))
		}

		vulnScanSummaries, err := storageClient.GetVulnerabilitySummaries()
		if err != nil {
			logger.L().Error("error getting vulnerability scan summaries", helpers.Error(err))
		}

		metrics.ProcessVulnNamespaceMetrics(vulnScanSummaries)
		metrics.ProcessVulnClusterMetrics(vulnScanSummaries)

		metrics.ProcessConfigscanClusterMetrics(configScanSummaries)
		metrics.ProcessConfigscanNamespaceMetrics(configScanSummaries)
	}

}
