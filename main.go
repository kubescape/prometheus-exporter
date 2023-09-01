package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yrs147/kubescape-exporter/collect"
)

var (
	clusterCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})
	relevantClusterCritical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_critical",
		Help: "Total number of relevant critical vulnerabilities in the cluster",
	})

	clusterHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})
	relevantClusterHigh = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_high",
		Help: "Total number of relevant high vulnerabilities in the cluster",
	})

	clusterMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})
	relevantClusterMedium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_medium",
		Help: "Total number of relevant medium vulnerabilities in the cluster",
	})

	clusterLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})
	relevantClusterLow = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_low",
		Help: "Total number of relevant low vulnerabilities in the cluster",
	})

	clusterNegligible = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_negligible",
		Help: "Total number of negligible vulnerabilities in the cluster",
	})
	relevantClusterNegligible = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_negligible",
		Help: "Total number of relevant negligible vulnerabilities in the cluster",
	})

	clusterUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})
	relevantClusterUnknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_unknown",
		Help: "Total number of relevant unknown vulnerabilities in the cluster",
	})
)

func init() {
	prometheus.MustRegister(clusterCritical)
	prometheus.MustRegister(relevantClusterCritical)
	prometheus.MustRegister(clusterHigh)
	prometheus.MustRegister(relevantClusterHigh)
	prometheus.MustRegister(clusterMedium)
	prometheus.MustRegister(relevantClusterMedium)
	prometheus.MustRegister(clusterLow)
	prometheus.MustRegister(relevantClusterLow)
	prometheus.MustRegister(clusterNegligible)
	prometheus.MustRegister(relevantClusterNegligible)
	prometheus.MustRegister(clusterUnknown)
	prometheus.MustRegister(relevantClusterUnknown)
}

func main() {

	// http.Handle("/metrics", promhttp.Handler())
	// log.Fatal(http.ListenAndServe(":8080", nil))

	yamlData, err := ioutil.ReadFile("test.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	// fmt.Println(string(yamlData))

	criticalAll, err := collect.GetSeverityValues(yamlData, "unknown")
	if err != nil {
		log.Fatalf("Error getting high severity values: %v", err)
	}

	fmt.Println("Critical : ", float64(criticalAll))

	// clusterCritical.Set(float64(criticalAll))

}
