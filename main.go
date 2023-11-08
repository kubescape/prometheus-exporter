package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yrs147/kubescape-exporter/api"
	"github.com/yrs147/kubescape-exporter/metrics"
	"k8s.io/client-go/util/homedir"
)

func main() {

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	var storageClient api.StorageClient
	storageClient = api.NewStorageClient()
	if err := storageClient.Initialize(*kubeconfig); err != nil {
		logger.L().Error("error initializing storage client", helpers.Error(err))
	}

	// Start Prometheus HTTP server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Prometheus metrics server started on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// monitor the severities in objects
	for {

		configScanSummaries, err := storageClient.GetConfigScanSummaries(*kubeconfig)
		if err != nil {
			logger.L().Error("error getting configuration scan summaries", helpers.Error(err))
		}

		vulnScanSummaries, err := storageClient.GetVulnerabilitySummaries(*kubeconfig)
		if err != nil {
			logger.L().Error("error getting vulnerability scan summaries", helpers.Error(err))
		}

		metrics.ProcessVulnNamespaceMetrics(vulnScanSummaries)
		metrics.ProcessVulnClusterMetrics(vulnScanSummaries)

		metrics.ProcessConfigscanClusterMetrics(configScanSummaries)
		metrics.ProcessConfigscanNamespaceMetrics(configScanSummaries)
	}
}
