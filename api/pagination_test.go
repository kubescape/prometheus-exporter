package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestListAllPagesRejectsIncompleteResults(t *testing.T) {
	pageErr := errors.New("page failed")
	tests := []struct {
		name  string
		pages []*v1beta1.VulnerabilityManifestSummaryList
		err   error
		want  error
	}{
		{name: "nil first page", pages: []*v1beta1.VulnerabilityManifestSummaryList{nil}, want: errNilPage},
		{name: "nil later page", pages: []*v1beta1.VulnerabilityManifestSummaryList{summaryList("next", "first"), nil}, want: errNilPage},
		{name: "repeated token", pages: []*v1beta1.VulnerabilityManifestSummaryList{summaryList("next", "first"), summaryList("next", "second")}, want: errRepeatedContinueToken},
		{name: "token cycle", pages: []*v1beta1.VulnerabilityManifestSummaryList{summaryList("a", "first"), summaryList("b", "second"), summaryList("a", "third")}, want: errRepeatedContinueToken},
		{name: "error with a page", pages: []*v1beta1.VulnerabilityManifestSummaryList{summaryList("", "partial")}, err: pageErr, want: pageErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			got, err := listAllPages(context.Background(),
				func(context.Context, metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
					if calls >= len(tt.pages) {
						t.Fatal("requested another page after an invalid response")
					}
					page := tt.pages[calls]
					calls++
					return page, tt.err
				}, appendSummaries)
			if !errors.Is(err, tt.want) || got != nil {
				t.Fatalf("got (%v, %v), want (nil, %v)", got, err, tt.want)
			}
			if calls != len(tt.pages) {
				t.Fatalf("made %d requests, want %d", calls, len(tt.pages))
			}
		})
	}
}

func TestListAllPagesWithCanceledContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{name: "canceled", ctx: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, want: context.Canceled},
		{name: "expired deadline", ctx: func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, want: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.ctx()
			defer cancel()
			got, err := listAllPages(ctx,
				func(context.Context, metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
					t.Fatal("requested a page with an already canceled context")
					return nil, nil
				}, appendSummaries)
			if !errors.Is(err, tt.want) || got != nil {
				t.Fatalf("got (%v, %v), want (nil, %v)", got, err, tt.want)
			}
		})
	}
}

func TestListAllPagesDiscardsResultsWhenCanceled(t *testing.T) {
	for _, token := range []string{"next", ""} {
		name := "between pages"
		if token == "" {
			name = "before returning final page"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			got, err := listAllPages(ctx,
				func(gotCtx context.Context, _ metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
					calls++
					if gotCtx != ctx {
						t.Fatal("page request did not receive the caller's context")
					}
					cancel()
					return summaryList(token, "partial"), nil
				}, appendSummaries)
			if !errors.Is(err, context.Canceled) || got != nil || calls != 1 {
				t.Fatalf("got (%v, %v) after %d requests, want a canceled read with no result", got, err, calls)
			}
		})
	}
}

func TestListAllPagesAcceptsEmptyInventory(t *testing.T) {
	got, err := listAllPages(context.Background(),
		func(context.Context, metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
			return summaryList(""), nil
		}, appendSummaries)
	if err != nil || got == nil || len(got.Items) != 0 || got.Continue != "" {
		t.Fatalf("got (%v, %v), want a successful empty list", got, err)
	}
}
