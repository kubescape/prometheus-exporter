package metrics

import (
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestProcessVulnWorkloadMetrics(t *testing.T) {
	vulnerabilityManifestSummaries := &v1beta1.VulnerabilityManifestSummaryList{
		Items: []v1beta1.VulnerabilityManifestSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "name1",
						"kubescape.io/workload-kind":      "deployment",
						"kubescape.io/workload-namespace": "namespace1",
					},
				},
				Spec: v1beta1.VulnerabilityManifestSummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 2,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      5,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      10,
							Relevant: 8,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      20,
							Relevant: 15,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "name2",
						"kubescape.io/workload-kind":      "deployment",
						"kubescape.io/workload-namespace": "namespace2",
					},
				},
				Spec: v1beta1.VulnerabilityManifestSummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      1,
							Relevant: 15,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      9,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 5,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      2,
							Relevant: 5,
						},
					},
				},
			},
		},
	}

	ProcessVulnWorkloadMetrics(vulnerabilityManifestSummaries)

	allCritical := &dto.Metric{}
	allHigh := &dto.Metric{}
	allMedium := &dto.Metric{}
	allLow := &dto.Metric{}
	allUnknown := &dto.Metric{}
	relevantCritical := &dto.Metric{}
	relevantHigh := &dto.Metric{}
	relevantMedium := &dto.Metric{}
	relevantLow := &dto.Metric{}
	relevantUnknown := &dto.Metric{}

	ggeWorkloadVulnCritical, _ := workloadVulnCritical.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnHigh, _ := workloadVulnHigh.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnMedium, _ := workloadVulnMedium.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnLow, _ := workloadVulnLow.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnUnknown, _ := workloadVulnUnknown.GetMetricWithLabelValues("namespace1", "name1", "deployment")

	ggeWorkloadVulnCriticalRelevant, _ := workloadVulnCriticalRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnHighRelevant, _ := workloadVulnHighRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnMediumRelevant, _ := workloadVulnMediumRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnLowRelevant, _ := workloadVulnLowRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment")
	ggeWorkloadVulnUnknownRelevant, _ := workloadVulnUnknownRelevant.GetMetricWithLabelValues("namespace1", "name1", "deployment")

	_ = ggeWorkloadVulnCritical.Write(allCritical)
	_ = ggeWorkloadVulnHigh.Write(allHigh)
	_ = ggeWorkloadVulnMedium.Write(allMedium)
	_ = ggeWorkloadVulnLow.Write(allLow)
	_ = ggeWorkloadVulnUnknown.Write(allUnknown)
	_ = ggeWorkloadVulnCriticalRelevant.Write(relevantCritical)
	_ = ggeWorkloadVulnHighRelevant.Write(relevantHigh)
	_ = ggeWorkloadVulnMediumRelevant.Write(relevantMedium)
	_ = ggeWorkloadVulnLowRelevant.Write(relevantLow)
	_ = ggeWorkloadVulnUnknownRelevant.Write(relevantUnknown)

	assert.Equal(t, float64(3), allCritical.Gauge.GetValue(), "Expected allCritical to be 3")
	assert.Equal(t, float64(5), allHigh.Gauge.GetValue(), "Expected allHigh to be 5")
	assert.Equal(t, float64(10), allMedium.Gauge.GetValue(), "Expected allMedium to be 10")
	assert.Equal(t, float64(20), allLow.Gauge.GetValue(), "Expected allLow to be 20")
	assert.Equal(t, float64(7), allUnknown.Gauge.GetValue(), "Expected allUnknown to be 7")
	assert.Equal(t, float64(2), relevantCritical.Gauge.GetValue(), "Expected relevantCritical to be 2")
	assert.Equal(t, float64(4), relevantHigh.Gauge.GetValue(), "Expected relevantHigh to be 4")
	assert.Equal(t, float64(8), relevantMedium.Gauge.GetValue(), "Expected relevantMedium to be 8")
	assert.Equal(t, float64(15), relevantLow.Gauge.GetValue(), "Expected relevantLow to be 15")
	assert.Equal(t, float64(3), relevantUnknown.Gauge.GetValue(), "Expected relevantUnknown to be 3")
}

func TestProcessVulnClusterMetrics(t *testing.T) {
	// Create a fake VulnerabilitySummaryList
	vulnSummary := &v1beta1.VulnerabilitySummaryList{
		Items: []v1beta1.VulnerabilitySummary{
			{
				Spec: v1beta1.VulnerabilitySummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 2,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      5,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      10,
							Relevant: 8,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      20,
							Relevant: 15,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
					},
				},
			},
			{
				Spec: v1beta1.VulnerabilitySummarySpec{
					Severities: v1beta1.SeveritySummary{
						Critical: v1beta1.VulnerabilityCounters{
							All:      1,
							Relevant: 15,
						},
						High: v1beta1.VulnerabilityCounters{
							All:      9,
							Relevant: 4,
						},
						Medium: v1beta1.VulnerabilityCounters{
							All:      3,
							Relevant: 5,
						},
						Low: v1beta1.VulnerabilityCounters{
							All:      7,
							Relevant: 3,
						},
						Unknown: v1beta1.VulnerabilityCounters{
							All:      2,
							Relevant: 5,
						},
					},
				},
			},
		},
	}

	totalCritical, totalHigh, totalMedium, totalLow, totalUnknown, relevantCritical, relevantHigh, relevantMedium, relevantLow, relevantUnknown := ProcessVulnClusterMetrics(vulnSummary)

	assert.Equal(t, 4, totalCritical, "Expected totalCritical to be 4")
	assert.Equal(t, 14, totalHigh, "Expected totalHigh to be 14")
	assert.Equal(t, 13, totalMedium, "Expected totalMedium to be 13")
	assert.Equal(t, 27, totalLow, "Expected totalLow to be 27")
	assert.Equal(t, 9, totalUnknown, "Expected totalUnknown to be 9")
	assert.Equal(t, 17, relevantCritical, "Expected relevantCritical to be 17")
	assert.Equal(t, 8, relevantHigh, "Expected relevantHigh to be 8")
	assert.Equal(t, 13, relevantMedium, "Expected relevantMedium to be 13")
	assert.Equal(t, 18, relevantLow, "Expected relevantLow to be 18")
	assert.Equal(t, 8, relevantUnknown, "Expected relevantUnknown to be 8")

}

func TestProcessConfigscanWorkloadMetrics(t *testing.T) {
	workloadConfigurationScanSummaries := &v1beta1.WorkloadConfigurationScanSummaryList{
		Items: []v1beta1.WorkloadConfigurationScanSummary{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubescape.io/workload-name":      "name1",
						"kubescape.io/workload-kind":      "ServiceAccount",
						"kubescape.io/workload-namespace": "namespace1",
					},
				},
				Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 3,
						High:     5,
						Medium:   10,
						Low:      20,
						Unknown:  7,
					},
				},
			},
		},
	}

	ProcessConfigscanWorkloadMetrics(workloadConfigurationScanSummaries)

	critical := &dto.Metric{}
	high := &dto.Metric{}
	medium := &dto.Metric{}
	low := &dto.Metric{}
	unknown := &dto.Metric{}

	ggeWorkloadCritical, _ := workloadCritical.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadHigh, _ := workloadHigh.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadMedium, _ := workloadMedium.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadLow, _ := workloadLow.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")
	ggeWorkloadUnknown, _ := workloadUnknown.GetMetricWithLabelValues("namespace1", "name1", "serviceaccount")

	_ = ggeWorkloadCritical.Write(critical)
	_ = ggeWorkloadHigh.Write(high)
	_ = ggeWorkloadMedium.Write(medium)
	_ = ggeWorkloadLow.Write(low)
	_ = ggeWorkloadUnknown.Write(unknown)

	assert.Equal(t, float64(3), critical.Gauge.GetValue(), "Expected allCritical to be 3")
	assert.Equal(t, float64(5), high.Gauge.GetValue(), "Expected allHigh to be 5")
	assert.Equal(t, float64(10), medium.Gauge.GetValue(), "Expected allMedium to be 10")
	assert.Equal(t, float64(20), low.Gauge.GetValue(), "Expected allLow to be 20")
	assert.Equal(t, float64(7), unknown.Gauge.GetValue(), "Expected allUnknown to be 7")
}

func TestProcessConfigscanClusterMetrics(t *testing.T) {

	csSummary := &v1beta1.ConfigurationScanSummaryList{
		Items: []v1beta1.ConfigurationScanSummary{
			{
				Spec: v1beta1.ConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 8,
						High:     10,
						Medium:   7,
						Low:      8,
						Unknown:  3,
					},
				},
			},
			{
				Spec: v1beta1.ConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 7,
						High:     2,
						Medium:   1,
						Low:      3,
						Unknown:  0,
					},
				},
			},
			{
				Spec: v1beta1.ConfigurationScanSummarySpec{
					Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      6,
						Unknown:  4,
					},
				},
			},
		},
	}

	totalCritical, totalHigh, totalMedium, totalLow, totalUnknown := ProcessConfigscanClusterMetrics(csSummary)

	assert.Equal(t, 16, totalCritical, "Expected totalCritical to be 16")
	assert.Equal(t, 14, totalHigh, "Expected totalHigh to be 14")
	assert.Equal(t, 11, totalMedium, "Expected totalMedium to be 11")
	assert.Equal(t, 17, totalLow, "Expected totalLow to be 17")
	assert.Equal(t, 7, totalUnknown, "Expected totalUnknown to be 7")
}
