package rbac

import (
	"context"
	"path"
	"strings"
)

type Manager struct {
	Perms PermissionRepo
	Roles RoleRepo
	Users UserRepo
	RP    RolePermissionRepo
	UR    UserRoleRepo
}

func (m *Manager) CreatePermission(ctx context.Context, p *Permission) error {
	return m.Perms.CreatePermission(ctx, p)
}

func (m *Manager) DeletePermission(ctx context.Context, id string) error {
	return m.Perms.DeletePermission(ctx, id)
}

func (m *Manager) GetPermission(ctx context.Context, id string) (*Permission, error) {
	return m.Perms.GetPermissionByID(ctx, id)
}

func (m *Manager) CreateRole(ctx context.Context, r *Role) error {
	return m.Roles.CreateRole(ctx, r)
}

func (m *Manager) DeleteRole(ctx context.Context, id string) error {
	return m.Roles.DeleteRole(ctx, id)
}

func (m *Manager) GetRole(ctx context.Context, id string) (*Role, error) {
	return m.Roles.GetRoleByID(ctx, id)
}

func (m *Manager) CreateUser(ctx context.Context, u *User) error {
	return m.Users.CreateUser(ctx, u)
}

func (m *Manager) DeleteUser(ctx context.Context, id string) error {
	return m.Users.DeleteUser(ctx, id)
}

func (m *Manager) GetUser(ctx context.Context, id string) (*User, error) {
	return m.Users.GetUserByID(ctx, id)
}

func (m *Manager) AssignPermissionToRole(ctx context.Context, roleID, permID string) error {
	return m.RP.AddRP(ctx, roleID, permID)
}

func (m *Manager) RemovePermissionFromRole(ctx context.Context, roleID, permID string) error {
	return m.RP.Remove(ctx, roleID, permID)
}

func (m *Manager) ListPermissionsForRole(ctx context.Context, roleID string) ([]string, error) {
	return m.RP.ListPermissions(ctx, roleID)
}

func (m *Manager) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	return m.UR.AddUR(ctx, userID, roleID)
}

func (m *Manager) UnassignRoleFromUser(ctx context.Context, userID, roleID string) error {
	return m.UR.RemoveUR(ctx, userID, roleID)
}

func (m *Manager) ListRolesForUser(ctx context.Context, userID string) ([]string, error) {
	return m.UR.ListRoles(ctx, userID)
}

// HasPermission checks whether user has a given permission via their roles.
func (m *Manager) HasPermission(ctx context.Context, userID, permID string) (bool, error) {
	roles, err := m.UR.ListRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		perms, err := m.RP.ListPermissions(ctx, r)
		if err != nil {
			return false, err
		}
		for _, p := range perms {
			if p == permID {
				return true, nil
			}
		}
	}
	return false, nil
}

// matchResource returns true if `resource` matches the glob-like
// `pattern`, where `*` is a single-segment wildcard and `**` matches
// zero or more dot-separated segments.
func matchResource(pattern, resource string) (bool, error) {
	if strings.Contains(pattern, "**") {
		// Only support a single “**” for simplicity:
		parts := strings.SplitN(pattern, "**", 2)
		prefix, suffix := parts[0], parts[1]
		// Must start with the prefix…
		if !strings.HasPrefix(resource, prefix) {
			return false, nil
		}
		// …and end with the suffix (suffix may be empty)
		if suffix != "" && !strings.HasSuffix(resource, suffix) {
			return false, nil
		}
		// Finally ensure the middle (whatever “**” stands for)
		// doesn’t “invert” the match length
		if len(resource) < len(prefix)+len(suffix) {
			return false, nil
		}
		return true, nil
	}
	// Fallback to single-segment globbing
	return path.Match(pattern, resource)
}

func (m *Manager) Can(ctx context.Context, userID, resource string, action Action) (bool, error) {
	roleIDs, err := m.UR.ListRoles(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, roleID := range roleIDs {
		permIDs, err := m.RP.ListPermissions(ctx, roleID)
		if err != nil {
			return false, err
		}
		for _, pid := range permIDs {
			perm, err := m.Perms.GetPermissionByID(ctx, pid)
			if err != nil {
				return false, err
			}
			if perm == nil {
				continue
			}

			// 3a) match resource (with ** support)
			okRes, err := matchResource(perm.Resource, resource)
			if err != nil {
				return false, err // e.g. malformed pattern
			}
			if !okRes {
				continue
			}

			// 3b) match action (only * single-segment wildcard)
			okAct, err := path.Match(string(perm.Action), string(action))
			if err != nil {
				return false, err
			}
			if okAct {
				return true, nil
			}
		}
	}

	return false, nil
}
