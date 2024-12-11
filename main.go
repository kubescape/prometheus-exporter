package main

import (
	"net/http"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/prometheus-exporter/api"
	"github.com/kubescape/prometheus-exporter/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	storageClient := api.NewStorageClient()

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		logger.L().Info("prometheus metrics server started", helpers.Int("port", 8080), helpers.String("path", "/metrics"))
		logger.L().Fatal(http.ListenAndServe(":8080", nil).Error())
	}()

	// monitor the severities in objects
	for {
		handleConfigScanSummaries(storageClient)
		handleVulnScanSummaries(storageClient)

		// TODO check if workload metrics should be enabled by default or if they should be enabled by an env variable
		handleWorkloadConfigScanSummaries(storageClient)
		handleWorkloadVulnScanSummaries(storageClient)

		// FIXME: get interval from config/env
		time.Sleep(120 * time.Second)
	}

}

func handleWorkloadConfigScanSummaries(storageClient *api.StorageClientImpl) {
	workloadConfigurationScanSummaries, err := storageClient.GetWorkloadConfigurationScanSummaries()
	if err != nil {
		logger.L().Warning("failed getting workload configuration scan summaries", helpers.Error(err))
		return
	}
	metrics.ProcessConfigscanWorkloadMetrics(workloadConfigurationScanSummaries)
}

func handleConfigScanSummaries(storageClient *api.StorageClientImpl) {
	configScanSummaries, err := storageClient.GetConfigScanSummaries()
	if err != nil {
		logger.L().Warning("failed getting configuration scan summaries", helpers.Error(err))
		return
	}

	metrics.ProcessConfigscanClusterMetrics(configScanSummaries)
	metrics.ProcessConfigscanNamespaceMetrics(configScanSummaries)
}

func handleWorkloadVulnScanSummaries(storageClient *api.StorageClientImpl) {
	vulnerabilityManifestSummaries, err := storageClient.GetVulnerabilityManifestSummaries()
	if err != nil {
		logger.L().Warning("failed getting vulnerability manifest summaries", helpers.Error(err))
		return
	}
	metrics.ProcessVulnWorkloadMetrics(vulnerabilityManifestSummaries)
}

func handleVulnScanSummaries(storageClient *api.StorageClientImpl) {
	vulnScanSummaries, err := storageClient.GetVulnerabilitySummaries()
	if err != nil {
		logger.L().Warning("failed getting vulnerability scan summaries", helpers.Error(err))
		return
	}

	metrics.ProcessVulnNamespaceMetrics(vulnScanSummaries)
	metrics.ProcessVulnClusterMetrics(vulnScanSummaries)
}
