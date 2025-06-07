// file: rbac/interfaces.go
package rbac

import (
	"context"
	"net/http"
)

// Core domain types (as before, but put in its own file)
type Action string

const (
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
	ActionAll    Action = "*" // ← matches every action
)

func HTTPMethodToAction(method string) Action {
	switch method {
	case http.MethodGet:
		return ActionRead
	case http.MethodPost:
		return ActionCreate
	case http.MethodPut:
		return ActionUpdate
	case http.MethodPatch:
		return ActionDelete
	default:
		return ActionAll
	}
}

type Permission struct {
	ID        string
	Resource  string
	Action    Action
	CreatedAt int64
}

type Role struct {
	ID          string
	Name        string
	Description string
	CreatedAt   int64
}

type User struct {
	ID        string
	Username  string
	Email     string
	CreatedAt int64
}

// Repository interfaces, storage-agnostic
type PermissionRepo interface {
	CreatePermission(ctx context.Context, p *Permission) error
	DeletePermission(ctx context.Context, id string) error
	GetPermissionByID(ctx context.Context, id string) (*Permission, error)
}

type RoleRepo interface {
	CreateRole(ctx context.Context, r *Role) error
	DeleteRole(ctx context.Context, id string) error
	GetRoleByID(ctx context.Context, id string) (*Role, error)
}

type UserRepo interface {
	CreateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	GetUserByID(ctx context.Context, id string) (*User, error)
}

// join-table repos
type RolePermissionRepo interface {
	AddRP(ctx context.Context, roleID, permID string) error
	Remove(ctx context.Context, roleID, permID string) error
	ListPermissions(ctx context.Context, roleID string) ([]string, error)
}

type UserRoleRepo interface {
	AddUR(ctx context.Context, userID, roleID string) error
	RemoveUR(ctx context.Context, userID, roleID string) error
	ListRoles(ctx context.Context, userID string) ([]string, error)
}
