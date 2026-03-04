// file: rbac/postgres_store.go
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ensure PostgresStore implements all interfaces:
var (
	_ PermissionRepo     = (*PostgresStore)(nil)
	_ RoleRepo           = (*PostgresStore)(nil)
	_ UserRepo           = (*PostgresStore)(nil)
	_ RolePermissionRepo = (*PostgresStore)(nil)
	_ UserRoleRepo       = (*PostgresStore)(nil)
	_ UserGroupRepo      = (*PostgresStore)(nil)
	_ GroupRoleRepo      = (*PostgresStore)(nil)
)

//
// ---------- PostgresStore Core ----------
//

type PostgresStore struct {
	db *pgxpool.Pool
}

// NewPostgresStore creates the store and ensures the schema is in place.
func NewPostgresStore(ctx context.Context, db *pgxpool.Pool) (*PostgresStore, error) {
	s := &PostgresStore{db: db}
	if err := s.EnsureSchema(ctx); err != nil {
		return nil, fmt.Errorf("postgres_store: ensure schema: %w", err)
	}
	return s, nil
}

// NewPostgresStoreManager wraps the store in a Manager and seeds the default role.
func NewPostgresStoreManager(ctx context.Context, db *pgxpool.Pool) (*Manager, error) {
	s, err := NewPostgresStore(ctx, db)
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

// EnsureSchema creates all required tables and unique indexes if they don't exist.
func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	ddl := `
	CREATE TABLE IF NOT EXISTS permissions (
		id          TEXT PRIMARY KEY,
		resource    TEXT        NOT NULL,
		action      TEXT        NOT NULL,
		created_at  BIGINT      NOT NULL DEFAULT 0,
		CONSTRAINT uq_permissions_resource_action UNIQUE (resource, action)
	);

	CREATE TABLE IF NOT EXISTS roles (
		id          TEXT PRIMARY KEY,
		name        TEXT        NOT NULL,
		description TEXT        NOT NULL DEFAULT '',
		created_at  BIGINT      NOT NULL DEFAULT 0,
		CONSTRAINT uq_roles_name UNIQUE (name)
	);

	CREATE TABLE IF NOT EXISTS users (
		id          TEXT PRIMARY KEY,
		username    TEXT        NOT NULL,
		email       TEXT        NOT NULL,
		created_at  BIGINT      NOT NULL DEFAULT 0,
		CONSTRAINT uq_users_username UNIQUE (username),
		CONSTRAINT uq_users_email    UNIQUE (email)
	);

	CREATE TABLE IF NOT EXISTS role_permissions (
		role_id       TEXT   NOT NULL,
		permission_id TEXT   NOT NULL,
		created_at    BIGINT NOT NULL DEFAULT 0,
		PRIMARY KEY (role_id, permission_id)
	);

	CREATE TABLE IF NOT EXISTS user_roles (
		user_id     TEXT   NOT NULL,
		role_id     TEXT   NOT NULL,
		assigned_at BIGINT NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id)
	);

	CREATE TABLE IF NOT EXISTS user_groups (
		id          TEXT PRIMARY KEY,
		user_id     TEXT   NOT NULL,
		group_name  TEXT   NOT NULL,
		created_at  BIGINT NOT NULL DEFAULT 0,
		CONSTRAINT uq_user_groups UNIQUE (user_id, group_name)
	);

	CREATE TABLE IF NOT EXISTS group_roles (
		group_name  TEXT   NOT NULL,
		role_id     TEXT   NOT NULL,
		created_at  BIGINT NOT NULL DEFAULT 0,
		PRIMARY KEY (group_name, role_id)
	);
	`

	_, err := s.db.Exec(ctx, ddl)
	return err
}

//
// ---------- UserRepo ----------
//

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, username, email, created_at FROM users WHERE id = $1`, id)

	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *PostgresStore) GetUserByMeta(ctx context.Context, meta map[string]interface{}) (*User, error) {
	// Build a simple equality filter from meta keys.
	// Only whitelisted columns are accepted to prevent SQL injection.
	allowed := map[string]bool{"id": true, "username": true, "email": true}

	args := make([]interface{}, 0, len(meta))
	where := ""
	i := 1
	for k, v := range meta {
		if !allowed[k] {
			return nil, fmt.Errorf("GetUserByMeta: unsupported field %q", k)
		}
		if where != "" {
			where += " AND "
		}
		where += fmt.Sprintf("%s = $%d", k, i)
		args = append(args, v)
		i++
	}
	if where == "" {
		return nil, errors.New("GetUserByMeta: no filter provided")
	}

	row := s.db.QueryRow(ctx,
		fmt.Sprintf(`SELECT id, username, email, created_at FROM users WHERE %s`, where),
		args...)

	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	u.CreatedAt = time.Now().Unix()

	_, err := s.db.Exec(ctx,
		`INSERT INTO users (id, username, email, created_at) VALUES ($1, $2, $3, $4)`,
		u.ID, u.Username, u.Email, u.CreatedAt)
	return err
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, user_id, group_name, created_at FROM user_groups WHERE user_id = $1`, userID)
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

func (s *PostgresStore) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, resource, action, created_at FROM permissions WHERE id = $1`, id)

	p := &Permission{}
	var action string
	err := row.Scan(&p.ID, &p.Resource, &action, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Action = Action(action)
	return p, nil
}

func (s *PostgresStore) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, resource, action, created_at FROM permissions WHERE resource = $1 AND action = $2`,
		resource, string(action))

	p := &Permission{}
	var act string
	err := row.Scan(&p.ID, &p.Resource, &act, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Action = Action(act)
	return p, nil
}

func (s *PostgresStore) CreatePermission(ctx context.Context, p *Permission) error {
	existing, _ := s.GetPermissionByResource(ctx, p.Resource, p.Action)
	if existing != nil {
		*p = *existing
		return nil
	}

	p.ID = uuid.New().String()
	p.CreatedAt = time.Now().Unix()

	_, err := s.db.Exec(ctx,
		`INSERT INTO permissions (id, resource, action, created_at) VALUES ($1, $2, $3, $4)`,
		p.ID, p.Resource, string(p.Action), p.CreatedAt)
	return err
}

func (s *PostgresStore) DeletePermission(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM permissions WHERE id = $1`, id)
	return err
}

//
// ---------- RoleRepo ----------
//

func (s *PostgresStore) CreateRole(ctx context.Context, r *Role) error {
	r.ID = uuid.New().String()
	r.CreatedAt = time.Now().Unix()

	_, err := s.db.Exec(ctx,
		`INSERT INTO roles (id, name, description, created_at) VALUES ($1, $2, $3, $4)`,
		r.ID, r.Name, r.Description, r.CreatedAt)
	return err
}

func (s *PostgresStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM roles WHERE name = $1`, name)

	r := &Role{}
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *PostgresStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM roles WHERE id = $1`, id)

	r := &Role{}
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *PostgresStore) DeleteRole(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) ListAllRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, description, created_at FROM roles`)
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

func (s *PostgresStore) AddRP(ctx context.Context, roleID, permID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id, created_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		roleID, permID, time.Now().Unix())
	return err
}

func (s *PostgresStore) Remove(ctx context.Context, roleID, permID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`,
		roleID, permID)
	return err
}

func (s *PostgresStore) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT permission_id FROM role_permissions WHERE role_id = $1`, roleID)
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

func (s *PostgresStore) AddUR(ctx context.Context, userID, roleID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, assigned_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		userID, roleID, time.Now().Unix())
	return err
}

func (s *PostgresStore) RemoveUR(ctx context.Context, userID, roleID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		userID, roleID)
	return err
}

func (s *PostgresStore) ListRoles(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT role_id FROM user_roles WHERE user_id = $1`, userID)

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

func (s *PostgresStore) AddUserToGroup(ctx context.Context, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	ug.ID = uuid.New().String()
	ug.CreatedAt = time.Now().Unix()

	_, err := s.db.Exec(ctx,
		`INSERT INTO user_groups (id, user_id, group_name, created_at)
		 VALUES ($1, $2, $3, $4)`,
		ug.ID, ug.UserID, ug.GroupName, ug.CreatedAt)
	return err
}

func (s *PostgresStore) RemoveUserFromGroup(ctx context.Context, groupName string, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	_, err := s.db.Exec(ctx,
		`DELETE FROM user_groups WHERE user_id = $1 AND group_name = $2`,
		ug.UserID, groupName)
	return err
}

func (s *PostgresStore) GetUsersByGroupID(ctx context.Context, groupName string) ([]*UserGroup, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, user_id, group_name, created_at FROM user_groups WHERE group_name = $1`, groupName)
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

func (s *PostgresStore) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO group_roles (group_name, role_id, created_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		groupID, roleID, time.Now().Unix())
	return err
}

func (s *PostgresStore) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM group_roles WHERE group_name = $1 AND role_id = $2`,
		groupID, roleID)
	return err
}

func (s *PostgresStore) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT role_id FROM group_roles WHERE group_name = $1`, groupID)
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
