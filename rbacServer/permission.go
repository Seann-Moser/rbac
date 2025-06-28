package rbacServer

import (
	"encoding/json"
	"github.com/Seann-Moser/rbac"
	"net/http"
)

// CreatePermissionHandler handles creating a new permission.
// POST /permissions/create
// Request Body: {"id": "new_perm_id", "name": "New Permission Name", "resource": "/api/data", "action": "read"}
func (s *Server) CreatePermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var newPerm rbac.Permission
	if err := json.NewDecoder(r.Body).Decode(&newPerm); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.CreatePermission(r.Context(), &newPerm); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create permission", err)
		return
	}

	writeJSONResponse(w, http.StatusCreated, map[string]string{"message": "Permission created successfully", "permission_id": newPerm.ID})
}

// DeletePermissionHandler handles deleting a permission.
// DELETE /permissions/delete?id=permID
func (s *Server) DeletePermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	permID := r.URL.Query().Get("id")
	if permID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing permission ID query parameter", nil)
		return
	}

	if err := s.RBACManager.DeletePermission(r.Context(), permID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete permission", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Permission deleted successfully"})
}

// GetPermissionHandler handles retrieving a permission by ID.
// GET /permissions/get?id=permID
func (s *Server) GetPermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	permID := r.URL.Query().Get("id")
	if permID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing permission ID query parameter", nil)
		return
	}

	perm, err := s.RBACManager.GetPermission(r.Context(), permID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get permission", err)
		return
	}
	if perm == nil {
		writeErrorResponse(w, http.StatusNotFound, "Permission not found", nil)
		return
	}

	writeJSONResponse(w, http.StatusOK, perm)
}

// AssignPermissionToRoleHandler handles assigning a permission to a role.
// POST /permissions/assign-to-role
// Request Body: {"role_id": "roleA", "perm_id": "permission1"}
func (s *Server) AssignPermissionToRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		RoleID string `json:"role_id"`
		PermID string `json:"perm_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.AssignPermissionToRole(r.Context(), req.RoleID, req.PermID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to assign permission to role", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Permission assigned to role successfully"})
}

// RemovePermissionFromRoleHandler handles removing a permission from a role.
// POST /permissions/remove-from-role
// Request Body: {"role_id": "roleA", "perm_id": "permission1"}
func (s *Server) RemovePermissionFromRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		RoleID string `json:"role_id"`
		PermID string `json:"perm_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.RemovePermissionFromRole(r.Context(), req.RoleID, req.PermID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to remove permission from role", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Permission removed from role successfully"})
}

// ListPermissionsForRoleHandler handles listing permissions for a role.
// GET /permissions/list-for-role?role_id=roleA
func (s *Server) ListPermissionsForRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	roleID := r.URL.Query().Get("role_id")
	if roleID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing role_id query parameter", nil)
		return
	}

	permissions, err := s.RBACManager.ListPermissionsForRole(r.Context(), roleID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list permissions for role", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, permissions)
}
