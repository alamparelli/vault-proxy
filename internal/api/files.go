package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/alessandrolamparelli/vault-proxy/internal/vault"
)

const maxFileSize = 5 << 20 // 5 MB

// filesRouter handles /files (list, upload)
func (s *Server) filesRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listFilesHandler(w, r)
	case http.MethodPost:
		s.uploadFileHandler(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// filesDetailRouter handles /files/{name} (download, delete)
func (s *Server) filesDetailRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.downloadFileHandler(w, r)
	case http.MethodDelete:
		s.deleteFileHandler(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) listFilesHandler(w http.ResponseWriter, r *http.Request) {
	files, err := s.store.ListFiles()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, files)
}

func (s *Server) uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)

	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		http.Error(w, `{"error":"invalid multipart form or file too large (max 5MB)"}`, http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, `{"error":"name field is required"}`, http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"file part is required"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, `{"error":"failed to read file"}`, http.StatusBadRequest)
		return
	}

	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	f := &vault.File{
		Name:     name,
		MimeType: mimeType,
		Data:     data,
	}
	if err := s.store.AddFile(f); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, f.Info())
}

func (s *Server) downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/files/")
	if name == "" {
		http.Error(w, `{"error":"missing file name"}`, http.StatusBadRequest)
		return
	}

	f, err := s.store.GetFile(name)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", f.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, f.Name))
	w.WriteHeader(http.StatusOK)
	w.Write(f.Data)
}

func (s *Server) deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/files/")
	if name == "" {
		http.Error(w, `{"error":"missing file name"}`, http.StatusBadRequest)
		return
	}

	if err := s.store.RemoveFile(name); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
