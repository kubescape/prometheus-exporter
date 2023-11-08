package metrics

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

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
