package api

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/alamparelli/vault-proxy/internal/vault"
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

	name, err := sanitizeFileName(r.FormValue("name"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
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
	w.Header().Set("Content-Disposition", safeContentDisposition(f.Name))
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

// sanitizeFileName validates and sanitizes a file name.
func sanitizeFileName(name string) (string, error) {
	if len(name) == 0 || len(name) > 255 {
		return "", fmt.Errorf("file name must be 1-255 characters")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("file name contains invalid characters")
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return "", fmt.Errorf("file name contains control characters")
		}
	}
	return name, nil
}

// safeContentDisposition returns an RFC 6266 compliant Content-Disposition header value.
func safeContentDisposition(filename string) string {
	// Sanitize for header safety: replace path separators and control chars
	clean := strings.Map(func(r rune) rune {
		if r < 32 || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, filename)
	return mime.FormatMediaType("attachment", map[string]string{"filename": clean})
}
