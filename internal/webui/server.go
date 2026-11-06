package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

//go:embed static/*
var assets embed.FS

type Server struct {
	checkpoint protocol.CheckpointResult
	store      *content.Store
}

func New(checkpoint protocol.CheckpointResult, store *content.Store) (*Server, error) {
	if err := protocol.ValidateCheckpointResultPolicy(checkpoint); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("content store is required")
	}
	return &Server{checkpoint: checkpoint, store: store}, nil
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	staticRoot, _ := fs.Sub(assets, "static")
	mux.Handle("/", http.FileServer(http.FS(staticRoot)))
	mux.HandleFunc("GET /standalone.html", server.handleStandalone)
	mux.HandleFunc("GET /api/checkpoint", server.handleCheckpoint)
	mux.HandleFunc("GET /api/content/{cid}", server.handleContent)
	return securityHeaders(mux)
}

func (server *Server) handleStandalone(writer http.ResponseWriter, _ *http.Request) {
	html, _, err := ExportStandalone(server.checkpoint, server.store)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")
	_, _ = writer.Write(html)
}

func (server *Server) handleCheckpoint(writer http.ResponseWriter, _ *http.Request) {
	view, err := localCheckpointView(server.checkpoint, server.store)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(writer).Encode(view); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func (server *Server) handleContent(writer http.ResponseWriter, request *http.Request) {
	contentCID := request.PathValue("cid")
	if err := content.ValidateCID(contentCID); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := server.store.Get(contentCID)
	if err != nil {
		http.Error(writer, "content unavailable", http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = io.Copy(writer, strings.NewReader(string(data)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}
