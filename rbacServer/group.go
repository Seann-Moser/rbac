package rbacServer

import (
	"encoding/json"
	"github.com/Seann-Moser/rbac"
	"net/http"
)

// AssignRoleToGroupHandler handles assigning a role to a group.
// POST /roles/assign-to-group
// Request Body: {"group_id": "group1", "role_id": "roleA"}
func (s *Server) AssignRoleToGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		GroupID string `json:"group_id"`
		RoleID  string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.AssignRoleToGroup(r.Context(), req.GroupID, req.RoleID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to assign role to group", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Role assigned to group successfully"})
}

// UnassignRoleFromGroupHandler handles unassigning a role from a group.
// POST /roles/unassign-from-group
// Request Body: {"group_id": "group1", "role_id": "roleA"}
func (s *Server) UnassignRoleFromGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		GroupID string `json:"group_id"`
		RoleID  string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.UnassignRoleFromGroup(r.Context(), req.GroupID, req.RoleID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to unassign role from group", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Role unassigned from group successfully"})
}

// ListRolesForGroupHandler handles listing roles for a group.
// GET /roles/list-for-group?group_id=group1
func (s *Server) ListRolesForGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing group_id query parameter", nil)
		return
	}

	roles, err := s.RBACManager.ListRolesForGroup(r.Context(), groupID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list roles for group", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, roles)
}

// CreateRoleHandler handles creating a new role.
// POST /roles/create
// Request Body: {"id": "new_role_id", "name": "New Role Name"}
func (s *Server) CreateRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var newRole rbac.Role
	if err := json.NewDecoder(r.Body).Decode(&newRole); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.CreateRole(r.Context(), &newRole); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create role", err)
		return
	}

	writeJSONResponse(w, http.StatusCreated, map[string]string{"message": "Role created successfully", "role_id": newRole.ID})
}

// DeleteRoleHandler handles deleting a role.
// DELETE /roles/delete?id=roleID
func (s *Server) DeleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	roleID := r.URL.Query().Get("id")
	if roleID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing role ID query parameter", nil)
		return
	}

	if err := s.RBACManager.DeleteRole(r.Context(), roleID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete role", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Role deleted successfully"})
}

// GetRoleHandler handles retrieving a role by ID.
// GET /roles/get?id=roleID
func (s *Server) GetRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	roleID := r.URL.Query().Get("id")
	if roleID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing role ID query parameter", nil)
		return
	}

	role, err := s.RBACManager.GetRole(r.Context(), roleID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get role", err)
		return
	}
	if role == nil {
		writeErrorResponse(w, http.StatusNotFound, "Role not found", nil)
		return
	}

	writeJSONResponse(w, http.StatusOK, role)
}

func (s *Server) ListRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	role, err := s.RBACManager.Roles.ListAllRoles(r.Context())
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get role", err)
		return
	}
	if role == nil {
		writeErrorResponse(w, http.StatusNotFound, "Role not found", nil)
		return
	}

	writeJSONResponse(w, http.StatusOK, role)
}
