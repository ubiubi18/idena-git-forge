package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

func TestCheckpointAndContentRoutes(t *testing.T) {
	store, err := content.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contentCID, err := store.Put([]byte("diff --git a/a b/a\n"), 2)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(protocol.CheckpointResult{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    protocol.CheckpointBlock{Epoch: 1},
		Repositories: []protocol.RepositoryResult{{
			Repository: "owner/repo",
			PRs: []protocol.PRResult{{
				PR: "pr-1", Revision: "rev_1", ActionCID: contentCID, BundleCID: contentCID, DiffCID: contentCID,
			}},
		}},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/checkpoint", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("checkpoint status = %d", response.Code)
	}
	var checkpoint struct {
		Repositories []struct {
			PRs []struct {
				PR           string                       `json:"pr"`
				Availability protocol.ContentAvailability `json:"availability"`
			} `json:"prs"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.Repositories[0].PRs[0].PR != "pr-1" {
		t.Fatal("checkpoint data mismatch")
	}
	availability := checkpoint.Repositories[0].PRs[0].Availability
	if !availability.Action || !availability.Bundle || !availability.Diff {
		t.Fatalf("local content availability missing from API view: %+v", availability)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/content/"+contentCID, nil))
	if response.Code != http.StatusOK || response.Body.String() != "diff --git a/a b/a\n" {
		t.Fatalf("content response = %d %q", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/standalone.html", nil))
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "Content-addressed checkpoint preview") {
		t.Fatalf("standalone response = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("standalone response lacks its restrictive CSP")
	}
}
