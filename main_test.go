package main

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type summaryClient struct {
	config    *v1beta1.ConfigurationScanSummaryList
	configErr error
	vuln      *v1beta1.VulnerabilitySummaryList
	vulnErr   error
}

func (c *summaryClient) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	return c.config, c.configErr
}

func (c *summaryClient) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	return c.vuln, c.vulnErr
}

func exposedSample(t *testing.T, sample string) bool {
	t.Helper()
	response := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 {
		t.Fatalf("metrics scrape returned HTTP %d", response.Code)
	}
	return strings.Contains(response.Body.String(), sample)
}

func TestFailedConfigSummaryListKeepsLastSuccessfulMetrics(t *testing.T) {
	client := &summaryClient{config: &v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-config-fetch-error"},
		Spec:       v1beta1.ConfigurationScanSummarySpec{Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{Critical: 4}},
	}}}}
	sample := `kubescape_controls_total_namespace_critical{namespace="audit-config-fetch-error"} 4`
	handleConfigScanSummaries(client)
	if !exposedSample(t, sample) {
		t.Fatal("successful summary list did not produce the metric")
	}

	// A later page may fail after one page was read. The handler must not treat
	// that incomplete inventory as an empty successful snapshot.
	client.config = &v1beta1.ConfigurationScanSummaryList{Items: []v1beta1.ConfigurationScanSummary{{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-config-partial"},
	}}}
	client.configErr = errors.New("page two failed")
	handleConfigScanSummaries(client)
	if !exposedSample(t, sample) {
		t.Fatal("failed summary list erased the last successful metric")
	}
	if exposedSample(t, `kubescape_controls_total_namespace_critical{namespace="audit-config-partial"}`) {
		t.Fatal("failed summary list exposed a partial inventory")
	}
}

func TestFailedVulnSummaryListKeepsLastSuccessfulMetrics(t *testing.T) {
	client := &summaryClient{vuln: &v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-vuln-fetch-error"},
		Spec:       v1beta1.VulnerabilitySummarySpec{Severities: v1beta1.SeveritySummary{Critical: v1beta1.VulnerabilityCounters{All: 6}}},
	}}}}
	sample := `kubescape_vulnerabilities_total_namespace_critical{namespace="audit-vuln-fetch-error"} 6`
	handleVulnScanSummaries(client)
	if !exposedSample(t, sample) {
		t.Fatal("successful summary list did not produce the metric")
	}

	client.vuln = &v1beta1.VulnerabilitySummaryList{Items: []v1beta1.VulnerabilitySummary{{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-vuln-partial"},
	}}}
	client.vulnErr = errors.New("page two failed")
	handleVulnScanSummaries(client)
	if !exposedSample(t, sample) {
		t.Fatal("failed summary list erased the last successful metric")
	}
	if exposedSample(t, `kubescape_vulnerabilities_total_namespace_critical{namespace="audit-vuln-partial"}`) {
		t.Fatal("failed summary list exposed a partial inventory")
	}
}
