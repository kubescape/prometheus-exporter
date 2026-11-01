package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func readerClient(t *testing.T, transport http.RoundTripper) *StorageClientImpl {
	t.Helper()
	client, err := spdxclient.NewForConfigAndClient(&rest.Config{Host: "http://storage.test"}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return &StorageClientImpl{clientset: client}
}

var summaryReaders = []struct {
	resource string
	kind     string
	read     func(*StorageClientImpl, context.Context) (runtime.Object, error)
}{
	{"vulnerabilitymanifestsummaries", "VulnerabilityManifestSummaryList", func(c *StorageClientImpl, ctx context.Context) (runtime.Object, error) {
		return c.GetVulnerabilityManifestSummaries(ctx)
	}},
	{"vulnerabilitysummaries", "VulnerabilitySummaryList", func(c *StorageClientImpl, ctx context.Context) (runtime.Object, error) {
		return c.GetVulnerabilitySummaries(ctx)
	}},
	{"workloadconfigurationscansummaries", "WorkloadConfigurationScanSummaryList", func(c *StorageClientImpl, ctx context.Context) (runtime.Object, error) {
		return c.GetWorkloadConfigurationScanSummaries(ctx)
	}},
	{"configurationscansummaries", "ConfigurationScanSummaryList", func(c *StorageClientImpl, ctx context.Context) (runtime.Object, error) {
		return c.GetConfigScanSummaries(ctx)
	}},
}

func TestSummaryReadersRequestEveryFullSpecPage(t *testing.T) {
	for _, reader := range summaryReaders {
		t.Run(reader.resource, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			calls := 0
			client := readerClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if got, ok := req.Context().Deadline(); !ok || !got.Equal(deadline) {
					t.Fatal("page request did not inherit the whole-read deadline")
				}
				if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/"+reader.resource) {
					t.Fatalf("unexpected summary request: %s %s", req.Method, req.URL.Path)
				}
				if got := req.URL.Query().Get("resourceVersion"); got != softwarecomposition.ResourceVersionFullSpec {
					t.Fatalf("resourceVersion = %q, want fullSpec", got)
				}
				wantToken, token, name := "", "next", "first"
				if calls == 2 {
					wantToken, token, name = "next", "", "second"
				} else if calls > 2 {
					t.Fatal("requested more than two pages")
				}
				if got := req.URL.Query().Get("continue"); got != wantToken {
					t.Fatalf("continue = %q, want %q", got, wantToken)
				}
				body, err := json.Marshal(map[string]interface{}{
					"apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
					"kind":       reader.kind,
					"metadata":   map[string]interface{}{"continue": token},
					"items": []interface{}{map[string]interface{}{
						"metadata": map[string]interface{}{"name": name},
						"spec":     map[string]interface{}{"severities": map[string]interface{}{"high": summaryHigh(reader.resource)}},
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			}))
			got, err := reader.read(client, ctx)
			if err != nil {
				t.Fatal(err)
			}
			items, err := meta.ExtractList(got)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, item := range items {
				accessor, err := meta.Accessor(item)
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, accessor.GetName())
				raw, err := json.Marshal(item)
				if err != nil {
					t.Fatal(err)
				}
				var decoded struct {
					Spec struct {
						Severities struct{ High json.RawMessage }
					}
				}
				if err := json.Unmarshal(raw, &decoded); err != nil {
					t.Fatal(err)
				}
				want, _ := json.Marshal(summaryHigh(reader.resource))
				if string(decoded.Spec.Severities.High) != string(want) {
					t.Fatalf("full spec lost in %s: got %s, want %s", accessor.GetName(), decoded.Spec.Severities.High, want)
				}
			}
			if calls != 2 || !reflect.DeepEqual(names, []string{"first", "second"}) {
				t.Fatalf("read %v in %d requests, want both pages", names, calls)
			}
			listMeta, err := meta.ListAccessor(got)
			if err != nil || listMeta.GetContinue() != "" {
				t.Fatalf("complete list retained a continuation token: %v", err)
			}
		})
	}
}

func summaryHigh(resource string) interface{} {
	if strings.Contains(resource, "configuration") {
		return 7
	}
	return map[string]int{"all": 7, "relevant": 3}
}

func TestSummaryReadersCancelInFlightRequest(t *testing.T) {
	for _, reader := range summaryReaders {
		t.Run(reader.resource, func(t *testing.T) {
			for _, page := range []string{"first", "second"} {
				t.Run(page+" page", func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					started := make(chan struct{})
					release := make(chan struct{})
					defer close(release)
					calls := 0
					client := readerClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						if page == "second" && calls == 1 {
							body, err := json.Marshal(map[string]interface{}{
								"apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1", "kind": reader.kind,
								"metadata": map[string]string{"continue": "next"}, "items": []interface{}{},
							})
							if err != nil {
								return nil, err
							}
							return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
						}
						close(started)
						select {
						case <-req.Context().Done():
							return nil, req.Context().Err()
						case <-release:
							return nil, errors.New("test finished before request cancellation")
						}
					}))
					done := make(chan error, 1)
					go func() {
						_, err := reader.read(client, ctx)
						done <- err
					}()
					select {
					case <-started:
					case <-time.After(5 * time.Second):
						t.Fatal("summary request did not start")
					}
					cancel()
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("read returned %v, want context.Canceled", err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("canceling the read did not cancel its HTTP request")
					}
				})
			}
		})
	}
}
