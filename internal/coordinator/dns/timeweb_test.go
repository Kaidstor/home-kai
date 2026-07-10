package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTimeweb mimics the empirically verified API model: records created via
// the zone with a `subdomain` field are visible only under their own fqdn.
func fakeTimeweb(t *testing.T) (*Timeweb, map[string]string) {
	t.Helper()
	records := map[string]string{} // fqdn → ip (single A record per fqdn, id=1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/domains/{fqdn}/dns-records", func(w http.ResponseWriter, r *http.Request) {
		fqdn := r.PathValue("fqdn")
		if _, ok := records[fqdn]; !ok {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dns_records": []map[string]any{{"id": 1, "type": "A"}},
		})
	})
	mux.HandleFunc("POST /api/v1/domains/{zone}/dns-records", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Value, Subdomain string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		records[body.Subdomain+"."+r.PathValue("zone")] = body.Value
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("PATCH /api/v1/domains/{fqdn}/dns-records/1", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Value string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		records[r.PathValue("fqdn")] = body.Value
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("DELETE /api/v1/domains/{fqdn}/dns-records/1", func(w http.ResponseWriter, r *http.Request) {
		delete(records, r.PathValue("fqdn"))
		w.WriteHeader(204)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	tw := NewTimeweb("example.com", "test-token")
	tw.HTTP = srv.Client()
	tw.HTTP.Transport = rewriteHost{srv.URL}
	return tw, records
}

// rewriteHost redirects twBaseURL requests to the test server.
type rewriteHost struct{ base string }

func (rw rewriteHost) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"
	r.URL.Host = strings.TrimPrefix(rw.base, "http://")
	return http.DefaultTransport.RoundTrip(r)
}

func TestTimewebEnsureDelete(t *testing.T) {
	tw, records := fakeTimeweb(t)
	ctx := context.Background()

	// Create (subdomain namespace does not exist yet → 404 from findA → POST).
	if err := tw.EnsureA(ctx, "dev1.kai.example.com", "100.87.0.5"); err != nil {
		t.Fatal(err)
	}
	if records["dev1.kai.example.com"] != "100.87.0.5" {
		t.Fatalf("records: %v", records)
	}

	// Ensure again with a new IP → PATCH, not a duplicate.
	if err := tw.EnsureA(ctx, "dev1.kai.example.com", "100.87.0.6"); err != nil {
		t.Fatal(err)
	}
	if records["dev1.kai.example.com"] != "100.87.0.6" || len(records) != 1 {
		t.Fatalf("update: %v", records)
	}

	// Outside the zone → error.
	if err := tw.EnsureA(ctx, "dev1.other.org", "100.87.0.7"); err == nil {
		t.Fatal("fqdn outside zone must fail")
	}

	// Delete, then delete again (missing record is not an error).
	if err := tw.DeleteA(ctx, "dev1.kai.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("delete: %v", records)
	}
	if err := tw.DeleteA(ctx, "dev1.kai.example.com"); err != nil {
		t.Fatal(err)
	}
}
