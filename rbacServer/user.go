package rbacServer

import (
	"encoding/json"
	"github.com/Seann-Moser/rbac"
	"net/http"
)

// CreateUserHandler handles creating a new user.
// POST /users/create
// Request Body: {"id": "new_user_id", "name": "New User Name"}
func (s *Server) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var newUser rbac.User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.CreateUser(r.Context(), &newUser); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create user", err)
		return
	}

	writeJSONResponse(w, http.StatusCreated, map[string]string{"message": "User created successfully", "user_id": newUser.ID})
}

// DeleteUserHandler handles deleting a user.
// DELETE /users/delete?id=userID
func (s *Server) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	userID := r.URL.Query().Get("id")
	if userID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing user ID query parameter", nil)
		return
	}

	if err := s.RBACManager.DeleteUser(r.Context(), userID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete user", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

// GetUserHandler handles retrieving a user by ID.
// GET /users/get?id=userID
func (s *Server) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	userID := r.URL.Query().Get("id")
	if userID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing user ID query parameter", nil)
		return
	}

	user, err := s.RBACManager.GetUser(r.Context(), userID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get user", err)
		return
	}
	if user == nil {
		writeErrorResponse(w, http.StatusNotFound, "User not found", nil)
		return
	}

	writeJSONResponse(w, http.StatusOK, user)
}

// AssignRoleToUserHandler handles assigning a role to a user.
// POST /users/assign-role
// Request Body: {"user_id": "user1", "role_id": "roleA"}
func (s *Server) AssignRoleToUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		UserID string `json:"user_id"`
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.AssignRoleToUser(r.Context(), req.UserID, req.RoleID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to assign role to user", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Role assigned to user successfully"})
}

// UnassignRoleFromUserHandler handles unassigning a role from a user.
// POST /users/unassign-role
// Request Body: {"user_id": "user1", "role_id": "roleA"}
func (s *Server) UnassignRoleFromUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		UserID string `json:"user_id"`
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.RBACManager.UnassignRoleFromUser(r.Context(), req.UserID, req.RoleID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to unassign role from user", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Role unassigned from user successfully"})
}

// ListRolesForUserHandler handles listing roles for a user.
// GET /users/list-roles?user_id=user1
func (s *Server) ListRolesForUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing user_id query parameter", nil)
		return
	}

	roles, err := s.RBACManager.ListRolesForUser(r.Context(), userID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list roles for user", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, roles)
}

// AddUserToGroupHandler handles adding a user to a group.
// POST /users/add-to-group
// Request Body: {"group_id": "group1", "user_id": "user1", "group_name": "GroupName"}
func (s *Server) AddUserToGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		GroupID   string `json:"group_id"`
		UserID    string `json:"user_id"`
		GroupName string `json:"group_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ug := &rbac.UserGroup{
		UserID:    req.UserID,
		GroupName: req.GroupName,
	}

	if err := s.RBACManager.AddUserToGroup(r.Context(), req.GroupID, ug); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to add user to group", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User added to group successfully"})
}

// RemoveUserFromGroupHandler handles removing a user from a group.
// POST /users/remove-from-group
// Request Body: {"group_id": "group1", "user_id": "user1", "group_name": "GroupName"}
func (s *Server) RemoveUserFromGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		GroupID   string `json:"group_id"`
		UserID    string `json:"user_id"`
		GroupName string `json:"group_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ug := &rbac.UserGroup{
		UserID:    req.UserID,
		GroupName: req.GroupName,
	}

	if err := s.RBACManager.RemoveUserFromGroup(r.Context(), req.GroupID, ug); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to remove user from group", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User removed from group successfully"})
}

// GetUsersByGroupIDHandler handles getting users by group ID.
// GET /users/list-by-group?group_id=group1
func (s *Server) GetUsersByGroupIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing group_id query parameter", nil)
		return
	}

	users, err := s.RBACManager.GetUsersByGroupID(r.Context(), groupID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get users by group ID", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, users)
}

// GetGroupsByUserIDHandler handles getting groups by user ID.
// GET /users/list-groups?user_id=user1
func (s *Server) GetGroupsByUserIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing user_id query parameter", nil)
		return
	}

	groups, err := s.RBACManager.GetGroupsByUserID(r.Context(), userID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get groups by user ID", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, groups)
}

// HasPermissionHandler checks if a user has a specific permission.
// GET /users/has-permission?user_id=user1&perm_id=permission1
func (s *Server) HasPermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	userID := r.URL.Query().Get("user_id")
	permID := r.URL.Query().Get("perm_id")

	if userID == "" || permID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Missing user_id or perm_id query parameters", nil)
		return
	}

	hasPermission, err := s.RBACManager.HasPermission(r.Context(), userID, permID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to check permission", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]bool{"has_permission": hasPermission})
}

// CanHandler checks if a user can perform an action on a resource.
// POST /users/can
// Request Body: {"user_id": "user1", "resource": "/api/data", "action": "read"}
func (s *Server) CanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		UserID   string `json:"user_id"`
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	can, err := s.RBACManager.Can(r.Context(), req.UserID, req.Resource, rbac.Action(req.Action))
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to perform authorization check", err)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]bool{"can_perform_action": can})
}
