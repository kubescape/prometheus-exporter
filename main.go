package main

import (
	"io/ioutil"
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yrs147/kubescape-exporter/collect"
)

var (
	kubescape_vulnerabilities_total_cluster_critical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_relevant_cluster_critical = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_critical",
		Help: "Total number of critical vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_cluster_high = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_relevant_cluster_high = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_high",
		Help: "Total number of high vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_cluster_medium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_relevant_cluster_medium = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_medium",
		Help: "Total number of medium vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_cluster_low = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_relevant_cluster_low = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_low",
		Help: "Total number of low vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_cluster_negligible = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_negligible",
		Help: "Total number of negligible vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_relevant_cluster_negligible = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_negligible",
		Help: "Total number of negligible vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_cluster_unknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})

	kubescape_vulnerabilities_total_relevant_cluster_unknown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubescape_vulnerabilities_total_relevant_cluster_unknown",
		Help: "Total number of unknown vulnerabilities in the cluster",
	})
)

func init() {
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_critical)
	prometheus.MustRegister(kubescape_vulnerabilities_total_relevant_cluster_critical)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_high)
	prometheus.MustRegister(kubescape_vulnerabilities_total_relevant_cluster_high)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_medium)
	prometheus.MustRegister(kubescape_vulnerabilities_total_relevant_cluster_medium)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_low)
	prometheus.MustRegister(kubescape_vulnerabilities_total_relevant_cluster_low)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_negligible)
	prometheus.MustRegister(kubescape_vulnerabilities_total_relevant_cluster_negligible)
	prometheus.MustRegister(kubescape_vulnerabilities_total_cluster_unknown)
	prometheus.MustRegister(kubescape_vulnerabilities_total_relevant_cluster_unknown)
}

func main() {

	// http.Handle("/metrics", promhttp.Handler())
	// log.Fatal(http.ListenAndServe(":8080", nil))

	yamlData, err := ioutil.ReadFile("vulnerability-mock.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	criticalAll, criticalRelevant, err := collect.GetSeverityValues(yamlData, "high")
	if err != nil {
		log.Fatalf("Error getting high severity values: %v", err)
	}

	// Update Prometheus metrics with labels
	kubescape_vulnerabilities_total_cluster_critical.Set(float64(criticalAll))
	kubescape_vulnerabilities_total_relevant_cluster_critical.Set(float64(criticalRelevant))


}
