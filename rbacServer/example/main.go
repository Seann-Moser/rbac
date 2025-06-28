package main

import (
	"fmt"
	"github.com/Seann-Moser/rbac"
	"github.com/Seann-Moser/rbac/rbacServer"
	"log"
	"net/http"
)

// main function to start the server (example)
func main() {
	// Initialize your RBAC Manager with actual repo implementations
	// For demonstration, we'll use placeholder repos. In a real app, these would be
	// connected to a database, in-memory store, etc.

	manager := rbac.NewMockRepoManager(rbac.NewMockRepo())

	srv := rbacServer.NewServer(manager)

	// Define HTTP routes
	http.HandleFunc("/roles/assign-to-group", srv.AssignRoleToGroupHandler)
	http.HandleFunc("/roles/unassign-from-group", srv.UnassignRoleFromGroupHandler)
	http.HandleFunc("/roles/list-for-group", srv.ListRolesForGroupHandler)
	http.HandleFunc("/roles/create", srv.CreateRoleHandler)
	http.HandleFunc("/roles/delete", srv.DeleteRoleHandler)
	http.HandleFunc("/roles/get", srv.GetRoleHandler)
	http.HandleFunc("/roles/get-all", srv.ListRoles)

	http.HandleFunc("/users/create", srv.CreateUserHandler)
	http.HandleFunc("/users/delete", srv.DeleteUserHandler)
	http.HandleFunc("/users/get", srv.GetUserHandler)
	http.HandleFunc("/users/assign-role", srv.AssignRoleToUserHandler)
	http.HandleFunc("/users/unassign-role", srv.UnassignRoleFromUserHandler)
	http.HandleFunc("/users/list-roles", srv.ListRolesForUserHandler)
	http.HandleFunc("/users/add-to-group", srv.AddUserToGroupHandler)
	http.HandleFunc("/users/remove-from-group", srv.RemoveUserFromGroupHandler)
	http.HandleFunc("/users/list-by-group", srv.GetUsersByGroupIDHandler)
	http.HandleFunc("/users/list-groups", srv.GetGroupsByUserIDHandler)
	http.HandleFunc("/users/has-permission", srv.HasPermissionHandler)
	http.HandleFunc("/users/can", srv.CanHandler)

	http.HandleFunc("/permissions/create", srv.CreatePermissionHandler)
	http.HandleFunc("/permissions/delete", srv.DeletePermissionHandler)
	http.HandleFunc("/permissions/get", srv.GetPermissionHandler)
	http.HandleFunc("/permissions/assign-to-role", srv.AssignPermissionToRoleHandler)
	http.HandleFunc("/permissions/remove-from-role", srv.RemovePermissionFromRoleHandler)
	http.HandleFunc("/permissions/list-for-role", srv.ListPermissionsForRoleHandler)
	http.HandleFunc("/manage", srv.MangementInterface)

	fmt.Println("Server listening on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
