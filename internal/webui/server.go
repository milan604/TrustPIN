package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/milan604/trustPIN/internal/trustpin"
)

//go:embed index.html
var webContent embed.FS

type server struct {
	service trustpin.Service
}

type apiAddRequest struct {
	Name     string `json:"name"`
	Secret   string `json:"secret"`
	Interval int64  `json:"interval"`
	Digits   int    `json:"digits"`
}

func Start(service trustpin.Service, port int) error {
	srv := server{service: service}
	mux := http.NewServeMux()

	mux.HandleFunc("/", srv.handleUI)
	mux.HandleFunc("/api/accounts", srv.handleAPIAccounts)
	mux.HandleFunc("/api/accounts/import", srv.handleImportQRAPI)
	mux.HandleFunc("/api/health", srv.handleAPIHealth)

	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)
	displayURL := fmt.Sprintf("http://trustpin.localhost:%d", port)
	fmt.Println()
	fmt.Println("  TrustPIN Web Dashboard")
	fmt.Printf("  Running at \033[1;36m%s\033[0m\n", displayURL)
	fmt.Printf("  Secure store: \033[0;37m%s\033[0m\n", service.StorePath)
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	return http.ListenAndServe(bindAddr, mux)
}

func (s server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, err := webContent.ReadFile("index.html")
	if err != nil {
		http.Error(w, "UI not available", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s server) handleAPIAccounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.handleListAccounts(w)
	case http.MethodPost:
		s.handleAddAccountAPI(w, r)
	case http.MethodPut:
		s.handleUpdateAccountAPI(w, r)
	case http.MethodDelete:
		s.handleDeleteAccountAPI(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s server) handleListAccounts(w http.ResponseWriter) {
	accounts, err := s.service.LoadAccounts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	response := make([]trustpin.AccountSnapshot, 0, len(accounts))
	for _, account := range accounts {
		response = append(response, trustpin.BuildAccountSnapshot(account))
	}

	writeJSON(w, http.StatusOK, response)
}

func (s server) handleAddAccountAPI(w http.ResponseWriter, r *http.Request) {
	var req apiAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if err := trustpin.ValidateAccountInput(req.Name, req.Secret); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if req.Interval <= 0 {
		req.Interval = trustpin.DefaultInterval
	}
	if req.Digits <= 0 {
		req.Digits = trustpin.DefaultDigits
	}
	if err := trustpin.ValidateDigits(req.Digits); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	summary, err := s.service.UpsertAccounts([]trustpin.Account{{
		Name:     req.Name,
		Secret:   req.Secret,
		Interval: req.Interval,
		Digits:   req.Digits,
	}})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

func (s server) handleUpdateAccountAPI(w http.ResponseWriter, r *http.Request) {
	currentName := strings.TrimSpace(r.URL.Query().Get("name"))
	if currentName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name query parameter is required"})
		return
	}

	var req apiAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "account name cannot be empty"})
		return
	}

	if req.Interval <= 0 {
		req.Interval = trustpin.DefaultInterval
	}
	if req.Digits <= 0 {
		req.Digits = trustpin.DefaultDigits
	}
	if err := trustpin.ValidateDigits(req.Digits); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.service.UpdateAccount(currentName, trustpin.Account{
		Name:     req.Name,
		Secret:   req.Secret,
		Interval: req.Interval,
		Digits:   req.Digits,
	}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "updated",
		"name":   req.Name,
	})
}

func (s server) handleDeleteAccountAPI(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name query parameter is required"})
		return
	}

	removed, err := s.service.DeleteAccount(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "deleted",
		"removed": removed,
	})
}

func (s server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	report, err := s.service.HealthReport()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (s server) handleImportQRAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or invalid form"})
		return
	}

	file, _, err := r.FormFile("qr")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	tmpFile, err := os.CreateTemp("", "trustpin-qr-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create temp file"})
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, file); err != nil {
		_ = tmpFile.Close()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save upload"})
		return
	}
	_ = tmpFile.Close()

	result, err := s.service.ImportAccountsFromQR(tmpPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"added":    result.Summary.Added,
		"replaced": result.Summary.Replaced,
		"skipped":  len(result.Skipped),
		"changes":  result.Summary.Changes,
		"details":  result.Skipped,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
