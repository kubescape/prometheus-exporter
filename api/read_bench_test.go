package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// BenchmarkSummaryReads measures full-spec JSON reads through the generated
// client over loopback HTTP. Responses are prepared outside the timed region;
// this measures client/transport cost, not Storage's aggregation or disk I/O.
func BenchmarkSummaryReads(b *testing.B) {
	for _, vulnerability := range []bool{false, true} {
		name := "workload_configuration"
		if vulnerability {
			name = "workload_vulnerability"
		}
		for _, count := range []int{100, 1000, 10000} {
			b.Run(fmt.Sprintf("%s/%d", name, count), func(b *testing.B) {
				const pageSize = 500
				var pages [][]byte
				var bytesPerRead int64
				for start := 0; start < count; start += pageSize {
					end := min(start+pageSize, count)
					token := ""
					if end < count {
						token = strconv.Itoa(len(pages) + 1)
					}
					config := &v1beta1.WorkloadConfigurationScanSummaryList{
						TypeMeta: metav1.TypeMeta{APIVersion: v1beta1.SchemeGroupVersion.String(), Kind: "WorkloadConfigurationScanSummaryList"},
						ListMeta: metav1.ListMeta{Continue: token},
					}
					vuln := &v1beta1.VulnerabilityManifestSummaryList{
						TypeMeta: metav1.TypeMeta{APIVersion: v1beta1.SchemeGroupVersion.String(), Kind: "VulnerabilityManifestSummaryList"},
						ListMeta: metav1.ListMeta{Continue: token},
					}
					for i := start; i < end; i++ {
						meta := metav1.ObjectMeta{
							Name: fmt.Sprintf("deployment-api-%05d", i), Namespace: fmt.Sprintf("team-%02d", i%20),
							Labels: map[string]string{
								"kubescape.io/workload-name": fmt.Sprintf("api-%05d", i), "kubescape.io/workload-kind": "Deployment",
								"kubescape.io/workload-namespace": fmt.Sprintf("team-%02d", i%20), "kubescape.io/workload-container-name": "app",
							},
						}
						if vulnerability {
							vuln.Items = append(vuln.Items, v1beta1.VulnerabilityManifestSummary{
								ObjectMeta: meta, Spec: v1beta1.VulnerabilityManifestSummarySpec{
									Severities: v1beta1.SeveritySummary{High: v1beta1.VulnerabilityCounters{All: 7, Relevant: 3}},
								},
							})
						} else {
							config.Items = append(config.Items, v1beta1.WorkloadConfigurationScanSummary{
								ObjectMeta: meta, Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
									Severities: v1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 7},
								},
							})
						}
					}
					var page []byte
					var err error
					if vulnerability {
						page, err = json.Marshal(vuln)
					} else {
						page, err = json.Marshal(config)
					}
					if err != nil {
						b.Fatal(err)
					}
					pages = append(pages, page)
					bytesPerRead += int64(len(page))
				}
				var requests atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					index := 0
					if token := r.URL.Query().Get("continue"); token != "" {
						var err error
						index, err = strconv.Atoi(token)
						if err != nil || index < 0 || index >= len(pages) {
							http.Error(w, "invalid continuation token", http.StatusBadRequest)
							return
						}
					}
					requests.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(pages[index])
				}))
				b.Cleanup(server.Close)
				// Disable client-side QPS throttling to isolate read/decode cost.
				clientset, err := spdxclient.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
				if err != nil {
					b.Fatal(err)
				}
				client := &StorageClientImpl{clientset: clientset}
				ctx := context.Background()
				b.ReportAllocs()
				b.SetBytes(bytesPerRead)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if vulnerability {
						list, err := client.GetVulnerabilityManifestSummaries(ctx)
						if err != nil || len(list.Items) != count {
							b.Fatalf("incomplete vulnerability read: %v", err)
						}
					} else {
						list, err := client.GetWorkloadConfigurationScanSummaries(ctx)
						if err != nil || len(list.Items) != count {
							b.Fatalf("incomplete configuration read: %v", err)
						}
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(requests.Load())/float64(b.N), "requests/op")
				b.ReportMetric(float64(bytesPerRead), "response_bytes/op")
			})
		}
	}
}
