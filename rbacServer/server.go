package rbacServer

import (
	_ "embed"
	"encoding/json"
	"github.com/Seann-Moser/rbac"
	"log"
	"net/http"
)

//go:embed rbac_mangement.html
var rbacManagementHTML string

type Server struct {
	RBACManager *rbac.Manager
}

// NewServer creates a new instance of your server with the RBAC manager
func NewServer(manager *rbac.Manager) *Server {
	return &Server{
		RBACManager: manager,
	}
}

// writeJSONResponse is a helper to send JSON responses
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

// writeErrorResponse is a helper to send error responses
func writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	log.Printf("Handler error (status %d): %s - %v", statusCode, message, err)
	writeJSONResponse(w, statusCode, map[string]string{"error": message})
}

func (s *Server) MangementInterface(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(rbacManagementHTML))
}
