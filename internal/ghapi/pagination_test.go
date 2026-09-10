package ghapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// GitHub is not obliged to repeat the Link header on a 304 Not Modified, and
// RFC 7232 only says it SHOULD. If the next page URL is taken solely from the
// revalidation response, a warm run stops after page one and silently reports
// a fraction of the estate as if it were all of it. That is the worst failure
// mode this tool has, because the output still looks like a complete report.
func TestPaginationSurvivesA304WithoutALinkHeader(t *testing.T) {
	var mu sync.Mutex
	var conditional int

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page := request.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}

		// Every page is unchanged on revalidation, and the 304 deliberately
		// omits Link to reproduce the conditions this guards against.
		if request.Header.Get("If-None-Match") != "" {
			mu.Lock()
			conditional++
			mu.Unlock()
			writer.WriteHeader(http.StatusNotModified)
			return
		}

		writer.Header().Set("ETag", `"page-`+page+`"`)
		if page == "1" {
			writer.Header().Set("Link", "<http://"+request.Host+"/items?page=2>; rel=\"next\"")
		}
		fmt.Fprintf(writer, `[{"page":%s}]`, page)
	}))
	defer server.Close()

	store := newMemoryCache()

	collectPages := func() []string {
		var pages []string
		client := newTestClient(server, store)
		err := client.GetPaginatedJSON(context.Background(), "items", func(page []byte) error {
			pages = append(pages, string(page))
			return nil
		})
		if err != nil {
			t.Fatalf("GetPaginatedJSON returned an error: %v", err)
		}
		return pages
	}

	cold := collectPages()
	if len(cold) != 2 {
		t.Fatalf("cold run collected %d pages, want 2: %v", len(cold), cold)
	}

	warm := collectPages()
	if len(warm) != len(cold) {
		t.Fatalf("warm run collected %d pages but the cold run collected %d; "+
			"a revalidated page must not truncate pagination: %v", len(warm), len(cold), warm)
	}

	mu.Lock()
	defer mu.Unlock()
	if conditional == 0 {
		t.Fatal("the warm run made no conditional requests, so the cache was not exercised")
	}
}

