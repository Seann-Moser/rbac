// file: rbac/mysql_store.go
package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// Ensure MySQLStore implements all interfaces:
var (
	_ PermissionRepo     = (*MySQLStore)(nil)
	_ RoleRepo           = (*MySQLStore)(nil)
	_ UserRepo           = (*MySQLStore)(nil)
	_ RolePermissionRepo = (*MySQLStore)(nil)
	_ UserRoleRepo       = (*MySQLStore)(nil)
	_ UserGroupRepo      = (*MySQLStore)(nil)
	_ GroupRoleRepo      = (*MySQLStore)(nil)
)

//
// ---------- MySQLStore Core ----------
//

type MySQLStore struct {
	db *sql.DB
}

// NewMySQLStore creates the store and ensures the schema is in place.
func NewMySQLStore(ctx context.Context, db *sql.DB) (*MySQLStore, error) {
	s := &MySQLStore{db: db}
	if err := s.EnsureSchema(ctx); err != nil {
		return nil, fmt.Errorf("mysql_store: ensure schema: %w", err)
	}
	return s, nil
}

// NewMySQLStoreManager wraps the store in a Manager and seeds the default role.
func NewMySQLStoreManager(ctx context.Context, db *sql.DB) (*Manager, error) {
	s, err := NewMySQLStore(ctx, db)
	if err != nil {
		return nil, err
	}

	def, _ := s.GetRoleByName(ctx, "default")
	if def == nil {
		def = &Role{Name: "default", Description: "Default role"}
		if createErr := s.CreateRole(ctx, def); createErr != nil {
			return nil, fmt.Errorf("failed to create default role: %w", createErr)
		}
	}

	return &Manager{
		Perms:           s,
		Roles:           s,
		Users:           s,
		RP:              s,
		UR:              s,
		UG:              s,
		DefaultRoleName: "default",
	}, nil
}

//
// ---------- Schema ----------
//

// EnsureSchema creates all required tables if they don't exist.
func (s *MySQLStore) EnsureSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE SCHEMA IF NOT EXISTS rbacv2;`,
		`CREATE TABLE IF NOT EXISTS rbacv2.permissions (
			id          VARCHAR(36)  NOT NULL PRIMARY KEY,
			resource    VARCHAR(255) NOT NULL,
			action      VARCHAR(64)  NOT NULL,
			created_at  BIGINT       NOT NULL DEFAULT 0,
			CONSTRAINT uq_permissions_resource_action UNIQUE (resource, action)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rbacv2.roles (
			id          VARCHAR(36)  NOT NULL PRIMARY KEY,
			name        VARCHAR(255) NOT NULL,
			description TEXT         NOT NULL,
			created_at  BIGINT       NOT NULL DEFAULT 0,
			CONSTRAINT uq_roles_name UNIQUE (name)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rbacv2.users (
			id          VARCHAR(36)  NOT NULL PRIMARY KEY,
			username    VARCHAR(255) NOT NULL,
			email       VARCHAR(255) NOT NULL,
			created_at  BIGINT       NOT NULL DEFAULT 0,
			CONSTRAINT uq_users_username UNIQUE (username),
			CONSTRAINT uq_users_email    UNIQUE (email)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rbacv2.role_permissions (
			role_id       VARCHAR(36) NOT NULL,
			permission_id VARCHAR(36) NOT NULL,
			created_at    BIGINT      NOT NULL DEFAULT 0,
			PRIMARY KEY (role_id, permission_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rbacv2.user_roles (
			user_id     VARCHAR(36) NOT NULL,
			role_id     VARCHAR(36) NOT NULL,
			assigned_at BIGINT      NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, role_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rbacv2.user_groups (
			id          VARCHAR(36)  NOT NULL PRIMARY KEY,
			user_id     VARCHAR(36)  NOT NULL,
			group_name  VARCHAR(255) NOT NULL,
			created_at  BIGINT       NOT NULL DEFAULT 0,
			CONSTRAINT uq_user_groups UNIQUE (user_id, group_name)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS rbacv2.group_roles (
			group_name  VARCHAR(255) NOT NULL,
			role_id     VARCHAR(36)  NOT NULL,
			created_at  BIGINT       NOT NULL DEFAULT 0,
			PRIMARY KEY (group_name, role_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

//
// ---------- UserRepo ----------
//

func (s *MySQLStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, email, created_at FROM rbacv2.users WHERE id = ?`, id)

	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *MySQLStore) GetUserByMeta(ctx context.Context, meta map[string]interface{}) (*User, error) {
	allowed := map[string]bool{"id": true, "username": true, "email": true}

	clauses := make([]string, 0, len(meta))
	args := make([]interface{}, 0, len(meta))
	for k, v := range meta {
		if !allowed[k] {
			return nil, fmt.Errorf("GetUserByMeta: unsupported field %q", k)
		}
		clauses = append(clauses, fmt.Sprintf("%s = ?", k))
		args = append(args, v)
	}
	if len(clauses) == 0 {
		return nil, errors.New("GetUserByMeta: no filter provided")
	}

	query := fmt.Sprintf(
		`SELECT id, username, email, created_at FROM rbacv2.users WHERE %s`,
		strings.Join(clauses, " AND "),
	)

	row := s.db.QueryRowContext(ctx, query, args...)
	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *MySQLStore) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	u.CreatedAt = time.Now().Unix()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rbacv2.users (id, username, email, created_at) VALUES (?, ?, ?, ?)`,
		u.ID, u.Username, u.Email, u.CreatedAt)
	return err
}

func (s *MySQLStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rbacv2.users WHERE id = ?`, id)
	return err
}

func (s *MySQLStore) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, group_name, created_at FROM rbacv2.user_groups WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*UserGroup
	for rows.Next() {
		ug := &UserGroup{}
		if err := rows.Scan(&ug.ID, &ug.UserID, &ug.GroupName, &ug.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ug)
	}
	return out, rows.Err()
}

//
// ---------- PermissionRepo ----------
//

func (s *MySQLStore) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, resource, action, created_at FROM rbacv2.permissions WHERE id = ?`, id)

	p := &Permission{}
	var action string
	err := row.Scan(&p.ID, &p.Resource, &action, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Action = Action(action)
	return p, nil
}

func (s *MySQLStore) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, resource, action, created_at FROM rbacv2.permissions WHERE resource = ? AND action = ?`,
		resource, string(action))

	p := &Permission{}
	var act string
	err := row.Scan(&p.ID, &p.Resource, &act, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Action = Action(act)
	return p, nil
}

func (s *MySQLStore) CreatePermission(ctx context.Context, p *Permission) error {
	existing, _ := s.GetPermissionByResource(ctx, p.Resource, p.Action)
	if existing != nil {
		*p = *existing
		return nil
	}

	p.ID = uuid.New().String()
	p.CreatedAt = time.Now().Unix()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rbacv2.permissions (id, resource, action, created_at) VALUES (?, ?, ?, ?)`,
		p.ID, p.Resource, string(p.Action), p.CreatedAt)
	return err
}

func (s *MySQLStore) DeletePermission(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rbacv2.permissions WHERE id = ?`, id)
	return err
}

//
// ---------- RoleRepo ----------
//

func (s *MySQLStore) CreateRole(ctx context.Context, r *Role) error {
	r.ID = uuid.New().String()
	r.CreatedAt = time.Now().Unix()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rbacv2.roles (id, name, description, created_at) VALUES (?, ?, ?, ?)`,
		r.ID, r.Name, r.Description, r.CreatedAt)
	return err
}

func (s *MySQLStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at FROM rbacv2.roles WHERE name = ?`, name)

	r := &Role{}
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *MySQLStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at FROM rbacv2.roles WHERE id = ?`, id)

	r := &Role{}
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *MySQLStore) DeleteRole(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rbacv2.roles WHERE id = ?`, id)
	return err
}

func (s *MySQLStore) ListAllRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, description, created_at FROM rbacv2.roles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Role
	for rows.Next() {
		r := &Role{}
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to decode role: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

//
// ---------- RolePermissionRepo ----------
//

func (s *MySQLStore) AddRP(ctx context.Context, roleID, permID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT IGNORE INTO rbacv2.role_permissions (role_id, permission_id, created_at) VALUES (?, ?, ?)`,
		roleID, permID, time.Now().Unix())
	return err
}

func (s *MySQLStore) Remove(ctx context.Context, roleID, permID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rbacv2.role_permissions WHERE role_id = ? AND permission_id = ?`,
		roleID, permID)
	return err
}

func (s *MySQLStore) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT permission_id FROM rbacv2.role_permissions WHERE role_id = ?`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

//
// ---------- UserRoleRepo ----------
//

func (s *MySQLStore) AddUR(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT IGNORE INTO rbacv2.user_roles (user_id, role_id, assigned_at) VALUES (?, ?, ?)`,
		userID, roleID, time.Now().Unix())
	return err
}

func (s *MySQLStore) RemoveUR(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rbacv2.user_roles WHERE user_id = ? AND role_id = ?`,
		userID, roleID)
	return err
}

func (s *MySQLStore) ListRoles(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_id FROM rbacv2.user_roles WHERE user_id = ?`, userID)

	var out []string

	if err != nil {
		// Still append the default role even on error, mirroring the Mongo behaviour.
		if r, _ := s.GetRoleByName(ctx, "default"); r != nil {
			out = append(out, r.ID)
		}
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Always include the default role.
	if r, _ := s.GetRoleByName(ctx, "default"); r != nil {
		out = append(out, r.ID)
	}
	return out, nil
}

//
// ---------- UserGroupRepo ----------
//

func (s *MySQLStore) AddUserToGroup(ctx context.Context, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	ug.ID = uuid.New().String()
	ug.CreatedAt = time.Now().Unix()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rbacv2.user_groups (id, user_id, group_name, created_at) VALUES (?, ?, ?, ?)`,
		ug.ID, ug.UserID, ug.GroupName, ug.CreatedAt)
	return err
}

func (s *MySQLStore) RemoveUserFromGroup(ctx context.Context, groupName string, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rbacv2.user_groups WHERE user_id = ? AND group_name = ?`,
		ug.UserID, groupName)
	return err
}

func (s *MySQLStore) GetUsersByGroupID(ctx context.Context, groupName string) ([]*UserGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, group_name, created_at FROM rbacv2.user_groups WHERE group_name = ?`, groupName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*UserGroup
	for rows.Next() {
		ug := &UserGroup{}
		if err := rows.Scan(&ug.ID, &ug.UserID, &ug.GroupName, &ug.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ug)
	}
	return out, rows.Err()
}

//
// ---------- GroupRoleRepo ----------
//

func (s *MySQLStore) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT IGNORE INTO rbacv2.group_roles (group_name, role_id, created_at) VALUES (?, ?, ?)`,
		groupID, roleID, time.Now().Unix())
	return err
}

func (s *MySQLStore) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rbacv2.group_roles WHERE group_name = ? AND role_id = ?`,
		groupID, roleID)
	return err
}

func (s *MySQLStore) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_id FROM rbacv2.group_roles WHERE group_name = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
