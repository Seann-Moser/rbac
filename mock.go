package rbac

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
)

// MockRepo is an in-memory implementation of all RBAC repository interfaces.
// It stores permissions, roles, users, user‐role, role‐permission, user‐group,
// and group‐role relationships in maps. This allows unit testing of Manager logic
// without a real database.
type MockRepo struct {
	perms      map[string]*Permission
	roles      map[string]*Role
	users      map[string]*User
	rolePerms  map[string]map[string]struct{}   // roleID -> set of permIDs
	userRoles  map[string]map[string]struct{}   // userID -> set of roleIDs
	userGroups map[string]map[string]*UserGroup // userID -> groupID -> *UserGroup
	groupUsers map[string]map[string]*UserGroup // groupID -> userID -> *UserGroup
	groupRoles map[string]map[string]struct{}   // groupID -> set of roleIDs
}

func (f *MockRepo) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	//TODO implement me
	panic("implement me")
}

func (f *MockRepo) GetUserByMeta(ctx context.Context, meta map[string]interface{}) (*User, error) {
	//TODO implement me
	panic("implement me")
}

func (f *MockRepo) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	//TODO implement me
	for _, role := range f.roles {
		if role.Name == name {
			return role, nil
		}
	}
	return nil, mongo.ErrNoDocuments
}

// NewMockRepo initializes a new MockRepo with empty data structures.
func NewMockRepo() *MockRepo {
	return &MockRepo{
		perms:      make(map[string]*Permission),
		roles:      make(map[string]*Role),
		users:      make(map[string]*User),
		rolePerms:  make(map[string]map[string]struct{}),
		userRoles:  make(map[string]map[string]struct{}),
		userGroups: make(map[string]map[string]*UserGroup),
		groupUsers: make(map[string]map[string]*UserGroup),
		groupRoles: make(map[string]map[string]struct{}),
	}
}

func NewMockRepoManager(m *MockRepo) *Manager {
	return &Manager{
		Perms:           m,
		Roles:           m,
		Users:           m,
		RP:              m,
		UR:              m,
		UG:              m,
		GR:              m,
		DefaultRoleName: "default",
	}
}

// PermissionRepo implementation
func (f *MockRepo) CreatePermission(ctx context.Context, p *Permission) error {
	f.perms[p.ID] = p
	return nil
}
func (f *MockRepo) DeletePermission(ctx context.Context, id string) error {
	delete(f.perms, id)
	return nil
}
func (f *MockRepo) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	if p, ok := f.perms[id]; ok {
		return p, nil
	}
	return nil, nil
}

// RoleRepo implementation
func (f *MockRepo) CreateRole(ctx context.Context, r *Role) error {
	f.roles[r.ID] = r
	return nil
}
func (f *MockRepo) DeleteRole(ctx context.Context, id string) error {
	delete(f.roles, id)
	return nil
}
func (f *MockRepo) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	if r, ok := f.roles[id]; ok {
		return r, nil
	}
	return nil, nil
}

// UserRepo implementation
func (f *MockRepo) CreateUser(ctx context.Context, u *User) error {
	f.users[u.ID] = u
	return nil
}
func (f *MockRepo) DeleteUser(ctx context.Context, id string) error {
	delete(f.users, id)
	return nil
}
func (f *MockRepo) GetUserByID(ctx context.Context, id string) (*User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, nil
}

// RolePermissionRepo implementation
func (f *MockRepo) AddRP(ctx context.Context, roleID, permID string) error {
	if f.rolePerms[roleID] == nil {
		f.rolePerms[roleID] = make(map[string]struct{})
	}
	f.rolePerms[roleID][permID] = struct{}{}
	return nil
}
func (f *MockRepo) Remove(ctx context.Context, roleID, permID string) error {
	if m, ok := f.rolePerms[roleID]; ok {
		delete(m, permID)
	}
	return nil
}
func (f *MockRepo) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	var out []string
	if m, ok := f.rolePerms[roleID]; ok {
		for pid := range m {
			out = append(out, pid)
		}
	}
	return out, nil
}

// UserRoleRepo implementation
func (f *MockRepo) AddUR(ctx context.Context, userID, roleID string) error {
	if f.userRoles[userID] == nil {
		f.userRoles[userID] = make(map[string]struct{})
	}
	f.userRoles[userID][roleID] = struct{}{}
	return nil
}
func (f *MockRepo) RemoveUR(ctx context.Context, userID, roleID string) error {
	if m, ok := f.userRoles[userID]; ok {
		delete(m, roleID)
	}
	return nil
}
func (f *MockRepo) ListRoles(ctx context.Context, userID string) ([]string, error) {
	var out []string
	if m, ok := f.userRoles[userID]; ok {
		for rid := range m {
			out = append(out, rid)
		}
	}
	return out, nil
}

// UserGroupRepo implementation
func (f *MockRepo) AddUserToGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	// by user
	if f.userGroups[ug.UserID] == nil {
		f.userGroups[ug.UserID] = make(map[string]*UserGroup)
	}
	f.userGroups[ug.UserID][groupID] = ug
	// by group
	if f.groupUsers[groupID] == nil {
		f.groupUsers[groupID] = make(map[string]*UserGroup)
	}
	f.groupUsers[groupID][ug.UserID] = ug
	return nil
}
func (f *MockRepo) RemoveUserFromGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	if m, ok := f.userGroups[ug.UserID]; ok {
		delete(m, groupID)
	}
	if m, ok := f.groupUsers[groupID]; ok {
		delete(m, ug.UserID)
	}
	return nil
}
func (f *MockRepo) GetUsersByGroupID(ctx context.Context, groupID string) ([]*UserGroup, error) {
	var out []*UserGroup
	if m, ok := f.groupUsers[groupID]; ok {
		for _, ug := range m {
			out = append(out, ug)
		}
	}
	return out, nil
}
func (f *MockRepo) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	var out []*UserGroup
	if m, ok := f.userGroups[userID]; ok {
		for _, ug := range m {
			out = append(out, ug)
		}
	}
	return out, nil
}

// GroupRoleRepo implementation
func (f *MockRepo) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	if f.groupRoles[groupID] == nil {
		f.groupRoles[groupID] = make(map[string]struct{})
	}
	f.groupRoles[groupID][roleID] = struct{}{}
	return nil
}
func (f *MockRepo) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	if m, ok := f.groupRoles[groupID]; ok {
		delete(m, roleID)
	}
	return nil
}
func (f *MockRepo) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	var out []string
	if m, ok := f.groupRoles[groupID]; ok {
		for rid := range m {
			out = append(out, rid)
		}
	}
	return out, nil
}
