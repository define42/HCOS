package controller

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/define42/HCOS/internal/protocol"
)

type role uint8

const (
	noRole role = iota
	nodeRole
	adminRole
)

// Handler exposes authenticated controller APIs. It is safe for concurrent use.
type Handler struct {
	store     *Store
	adminHash [32]byte
	nodeHash  map[string][32]byte
	mux       *http.ServeMux
}

// NewHandler connects the validated configuration and persistent store.
func NewHandler(config Config, store *Store) (*Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("controller store is required")
	}
	handler := &Handler{
		store:     store,
		adminHash: sha256.Sum256([]byte(config.AdminToken)),
		nodeHash:  make(map[string][32]byte, len(config.Nodes)),
		mux:       http.NewServeMux(),
	}
	for _, node := range config.Nodes {
		handler.nodeHash[node.ID] = sha256.Sum256([]byte(node.Token))
	}
	handler.mux.HandleFunc("GET /healthz", handler.health)
	handler.mux.HandleFunc("GET /readyz", handler.ready)
	handler.mux.HandleFunc("GET /v1/nodes/{id}/desired", handler.getDesired)
	handler.mux.HandleFunc("PUT /v1/nodes/{id}/desired", handler.putDesired)
	handler.mux.HandleFunc("POST /v1/nodes/{id}/report", handler.postReport)
	handler.mux.HandleFunc("GET /v1/nodes/{id}/report", handler.getReport)
	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Ready(r.Context()); err != nil {
		http.Error(w, "controller store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

func (h *Handler) getDesired(w http.ResponseWriter, r *http.Request) {
	id, access, ok := h.authorizeNodePath(w, r)
	if !ok {
		return
	}
	if access != adminRole && access != nodeRole {
		unauthorized(w)
		return
	}
	desired, err := h.store.Desired(r.Context(), id)
	if err != nil {
		http.Error(w, "controller store unavailable", http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, desired)
}

func (h *Handler) putDesired(w http.ResponseWriter, r *http.Request) {
	id, access, ok := h.authorizeNodePath(w, r)
	if !ok {
		return
	}
	if access != adminRole {
		http.Error(w, "admin authorization required", http.StatusForbidden)
		return
	}
	var desired protocol.DesiredState
	if status := decodeRequestJSON(w, r, maxDesiredBytes, &desired); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	if err := validateDesired(desired); err != nil {
		http.Error(w, "invalid desired state: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.PutDesired(r.Context(), id, desired); err != nil {
		if errors.Is(err, ErrRevisionConflict) {
			http.Error(w, "revision already has different content", http.StatusConflict)
			return
		}
		if errors.Is(err, ErrPayloadTooLarge) {
			http.Error(w, "desired state exceeds size limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "controller store unavailable", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) postReport(w http.ResponseWriter, r *http.Request) {
	id, access, ok := h.authorizeNodePath(w, r)
	if !ok {
		return
	}
	if access != nodeRole {
		http.Error(w, "node authorization required", http.StatusForbidden)
		return
	}
	var report protocol.Report
	if status := decodeRequestJSON(w, r, maxReportBytes, &report); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	if err := validateReport(id, report); err != nil {
		http.Error(w, "invalid report: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.PutReport(r.Context(), id, report); err != nil {
		http.Error(w, "controller store unavailable", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getReport(w http.ResponseWriter, r *http.Request) {
	id, access, ok := h.authorizeNodePath(w, r)
	if !ok {
		return
	}
	if access != adminRole {
		http.Error(w, "admin authorization required", http.StatusForbidden)
		return
	}
	report, exists, err := h.store.Report(r.Context(), id)
	if err != nil {
		http.Error(w, "controller store unavailable", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.NotFound(w, r)
		return
	}
	writeJSONResponse(w, http.StatusOK, report)
}

func (h *Handler) authorizeNodePath(w http.ResponseWriter, r *http.Request) (string, role, bool) {
	id := r.PathValue("id")
	if !validNodeID(id) {
		http.NotFound(w, r)
		return "", noRole, false
	}
	access := h.authenticate(r, id)
	if access == noRole {
		unauthorized(w)
		return "", noRole, false
	}
	if _, exists := h.nodeHash[id]; !exists {
		http.NotFound(w, r)
		return "", noRole, false
	}
	return id, access, true
}

func (h *Handler) authenticate(r *http.Request, nodeID string) role {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return noRole
	}
	scheme, token, ok := strings.Cut(headers[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !validBearerToken(token) {
		return noRole
	}
	tokenHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(tokenHash[:], h.adminHash[:]) == 1 {
		return adminRole
	}
	nodeHash, exists := h.nodeHash[nodeID]
	if exists && subtle.ConstantTimeCompare(tokenHash[:], nodeHash[:]) == 1 {
		return nodeRole
	}
	return noRole
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func decodeRequestJSON(w http.ResponseWriter, r *http.Request, limit int64, target any) int {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return http.StatusUnsupportedMediaType
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return decodeErrorStatus(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return http.StatusBadRequest
		}
		return decodeErrorStatus(err)
	}
	return 0
}

func decodeErrorStatus(err error) int {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	data, err := encodeJSON(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
