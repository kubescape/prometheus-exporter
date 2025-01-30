package main

import (
	"net/http"
	"os"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/prometheus-exporter/api"
	"github.com/kubescape/prometheus-exporter/metrics"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/watch"
)

func main() {

	storageClient := api.NewStorageClient()

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		logger.L().Info("prometheus metrics server started", helpers.Int("port", 8080), helpers.String("path", "/metrics"))
		logger.L().Fatal(http.ListenAndServe(":8080", nil).Error())
	}()

	if os.Getenv("ENABLE_WORKLOAD_METRICS") == "true" {
		go watchWorkloadConfigScanSummaries(storageClient)
		go watchWorkloadVulnScanSummaries(storageClient)
	}

	// monitor the severities in objects (no watch available)
	for {
		handleConfigScanSummaries(storageClient)
		handleVulnScanSummaries(storageClient)

		// FIXME: get interval from config/env
		time.Sleep(120 * time.Second)
	}

}

func watchWorkloadVulnScanSummaries(storageClient *api.StorageClientImpl) {
	// insert the existing items
	handleWorkloadVulnScanSummaries(storageClient)
	// watch for new items
	watcher, _ := storageClient.WatchVulnerabilityManifestSummaries()
	for event := range watcher.ResultChan() {
		item, ok := event.Object.(*v1beta1.VulnerabilityManifestSummary)
		if !ok {
			continue
		}
		logger.L().Debug("received event", helpers.Interface("event", event), helpers.String("name", item.Name))
		if event.Type == watch.Added || event.Type == watch.Modified {
			metrics.ProcessVulnWorkloadMetrics(&v1beta1.VulnerabilityManifestSummaryList{
				Items: []v1beta1.VulnerabilityManifestSummary{*item},
			})
		}

		if event.Type == watch.Deleted {
			metrics.DeleteVulnWorkloadMetric(item)
		}
	}
}

func watchWorkloadConfigScanSummaries(storageClient *api.StorageClientImpl) {
	// insert the existing items
	handleWorkloadConfigScanSummaries(storageClient)
	// watch for new items
	watcher, _ := storageClient.WatchWorkloadConfigurationScanSummaries()
	for event := range watcher.ResultChan() {
		item, ok := event.Object.(*v1beta1.WorkloadConfigurationScanSummary)
		if !ok {
			continue
		}
		logger.L().Debug("received event", helpers.Interface("event", event), helpers.String("name", item.Name))
		if event.Type == watch.Added || event.Type == watch.Modified {
			metrics.ProcessConfigscanWorkloadMetrics(&v1beta1.WorkloadConfigurationScanSummaryList{
				Items: []v1beta1.WorkloadConfigurationScanSummary{*item},
			})
		}

		if event.Type == watch.Deleted {
			metrics.DeleteConfigscanWorkloadMetric(item)
		}
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
