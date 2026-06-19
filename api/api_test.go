package api

import (
	"errors"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func summaryList(continueToken string, names ...string) *v1beta1.VulnerabilityManifestSummaryList {
	list := &v1beta1.VulnerabilityManifestSummaryList{}
	list.Continue = continueToken
	for _, n := range names {
		list.Items = append(list.Items, v1beta1.VulnerabilityManifestSummary{
			ObjectMeta: metav1.ObjectMeta{Name: n},
		})
	}
	return list
}

func appendSummaries(dst, src *v1beta1.VulnerabilityManifestSummaryList) {
	dst.Items = append(dst.Items, src.Items...)
}

func TestListAllPages_FollowsContinueToken(t *testing.T) {
	// Three pages: the first two return a continue token, the last is partial.
	pages := []*v1beta1.VulnerabilityManifestSummaryList{
		summaryList("token-1", "a", "b"),
		summaryList("token-2", "c", "d"),
		summaryList("", "e"),
	}
	var seenContinue []string
	call := 0

	got, err := listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
			// Every page must keep requesting the full spec.
			if opts.ResourceVersion != softwarecomposition.ResourceVersionFullSpec {
				t.Fatalf("page %d: ResourceVersion = %q, want %q", call, opts.ResourceVersion, softwarecomposition.ResourceVersionFullSpec)
			}
			seenContinue = append(seenContinue, opts.Continue)
			page := pages[call]
			call++
			return page, nil
		},
		appendSummaries,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The continue token from each page must be threaded into the next request.
	wantContinue := []string{"", "token-1", "token-2"}
	if len(seenContinue) != len(wantContinue) {
		t.Fatalf("made %d requests, want %d", len(seenContinue), len(wantContinue))
	}
	for i := range wantContinue {
		if seenContinue[i] != wantContinue[i] {
			t.Errorf("request %d Continue = %q, want %q", i, seenContinue[i], wantContinue[i])
		}
	}

	// All items from every page must be aggregated.
	var gotNames []string
	for _, item := range got.Items {
		gotNames = append(gotNames, item.Name)
	}
	wantNames := []string{"a", "b", "c", "d", "e"}
	if len(gotNames) != len(wantNames) {
		t.Fatalf("got %d items %v, want %d %v", len(gotNames), gotNames, len(wantNames), wantNames)
	}
	for i := range wantNames {
		if gotNames[i] != wantNames[i] {
			t.Errorf("item %d = %q, want %q", i, gotNames[i], wantNames[i])
		}
	}

	// The accumulated list must not advertise a stale continue token.
	if got.Continue != "" {
		t.Errorf("aggregated list Continue = %q, want empty", got.Continue)
	}
}

func TestListAllPages_SinglePage(t *testing.T) {
	call := 0
	got, err := listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
			call++
			return summaryList("", "only"), nil
		},
		appendSummaries,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call != 1 {
		t.Errorf("made %d requests, want 1", call)
	}
	if len(got.Items) != 1 || got.Items[0].Name != "only" {
		t.Errorf("got items %v, want [only]", got.Items)
	}
}

func TestListAllPages_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	// First page succeeds, second page errors out.
	call := 0
	got, err := listAllPages(
		func(opts metav1.ListOptions) (*v1beta1.VulnerabilityManifestSummaryList, error) {
			call++
			if call == 1 {
				return summaryList("token-1", "a"), nil
			}
			return nil, wantErr
		},
		appendSummaries,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Errorf("got = %v, want nil on error", got)
	}
}
