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
	Name      string   `json:"name"`
	Secret    string   `json:"secret"`
	Interval  int64    `json:"interval"`
	Digits    int      `json:"digits"`
	Algorithm string   `json:"algorithm"`
	Type      string   `json:"type"`
	Counter   int64    `json:"counter"`
	Tags      []string `json:"tags"`
	Favorite  bool     `json:"favorite"`
	Notes     string   `json:"notes"`
	SortOrder int      `json:"sortOrder"`
	Archived  bool     `json:"archived"`
}

func Start(service trustpin.Service, port int) error {
	srv := server{service: service}
	mux := http.NewServeMux()

	mux.HandleFunc("/", srv.handleUI)
	mux.HandleFunc("/api/accounts", srv.handleAPIAccounts)
	mux.HandleFunc("/api/accounts/import", srv.handleImportQRAPI)
	mux.HandleFunc("/api/accounts/qr", srv.handleAccountQR)
	mux.HandleFunc("/api/accounts/reorder", srv.handleReorderAPI)
	mux.HandleFunc("/api/accounts/archive", srv.handleArchiveAPI)
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
		Name:      req.Name,
		Secret:    req.Secret,
		Interval:  req.Interval,
		Digits:    req.Digits,
		Algorithm: req.Algorithm,
		Type:      req.Type,
		Counter:   req.Counter,
		Tags:      req.Tags,
		Favorite:  req.Favorite,
		Notes:     req.Notes,
		SortOrder: req.SortOrder,
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
		Name:      req.Name,
		Secret:    req.Secret,
		Interval:  req.Interval,
		Digits:    req.Digits,
		Algorithm: req.Algorithm,
		Type:      req.Type,
		Counter:   req.Counter,
		Tags:      req.Tags,
		Favorite:  req.Favorite,
		Notes:     req.Notes,
		SortOrder: req.SortOrder,
		Archived:  req.Archived,
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

func (s server) handleAccountQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name query parameter is required"})
		return
	}

	accounts, err := s.service.LoadAccounts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var target *trustpin.Account
	nameKey := strings.ToLower(name)
	for _, a := range accounts {
		if strings.ToLower(strings.TrimSpace(a.Name)) == nameKey {
			target = &a
			break
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}

	png, err := trustpin.GenerateQRCodePNG(*target, 256)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate QR code"})
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s server) handleReorderAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var order []struct {
		Name      string `json:"name"`
		SortOrder int    `json:"sortOrder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&order); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	accounts, err := s.service.LoadAccounts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	orderMap := make(map[string]int, len(order))
	for _, o := range order {
		orderMap[strings.ToLower(strings.TrimSpace(o.Name))] = o.SortOrder
	}

	for i, a := range accounts {
		if so, ok := orderMap[strings.ToLower(strings.TrimSpace(a.Name))]; ok {
			accounts[i].SortOrder = so
		}
	}

	if err := s.service.SaveAccounts(accounts); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "reordered"})
}

func (s server) handleArchiveAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		Name     string `json:"name"`
		Archived bool   `json:"archived"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	if err := s.service.SetAccountArchived(name, req.Archived); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	action := "archived"
	if !req.Archived {
		action = "restored"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": action, "name": name})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
