package rbac

import (
	"context"
	"testing"
)

// FakeRepo is an in-memory implementation of all RBAC repository interfaces.
// It stores permissions, roles, users, and their relationships in maps.
// This allows unit testing of Manager logic without a real database.

type FakeRepo struct {
	perms     map[string]*Permission
	roles     map[string]*Role
	users     map[string]*User
	rolePerms map[string]map[string]struct{} // roleID -> set of permIDs
	userRoles map[string]map[string]struct{} // userID -> set of roleIDs
}

// NewFakeRepo initializes a new FakeRepo with empty data structures.
func NewFakeRepo() *FakeRepo {
	return &FakeRepo{
		perms:     make(map[string]*Permission),
		roles:     make(map[string]*Role),
		users:     make(map[string]*User),
		rolePerms: make(map[string]map[string]struct{}),
		userRoles: make(map[string]map[string]struct{}),
	}
}

// PermissionRepo implementation
func (f *FakeRepo) CreatePermission(ctx context.Context, p *Permission) error {
	f.perms[p.ID] = p
	return nil
}
func (f *FakeRepo) DeletePermission(ctx context.Context, id string) error {
	delete(f.perms, id)
	return nil
}
func (f *FakeRepo) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	if p, ok := f.perms[id]; ok {
		return p, nil
	}
	return nil, nil
}

// RoleRepo implementation
func (f *FakeRepo) CreateRole(ctx context.Context, r *Role) error {
	f.roles[r.ID] = r
	return nil
}
func (f *FakeRepo) DeleteRole(ctx context.Context, id string) error {
	delete(f.roles, id)
	return nil
}
func (f *FakeRepo) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	if r, ok := f.roles[id]; ok {
		return r, nil
	}
	return nil, nil
}

// UserRepo implementation
func (f *FakeRepo) CreateUser(ctx context.Context, u *User) error {
	f.users[u.ID] = u
	return nil
}
func (f *FakeRepo) DeleteUser(ctx context.Context, id string) error {
	delete(f.users, id)
	return nil
}
func (f *FakeRepo) GetUserByID(ctx context.Context, id string) (*User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, nil
}

// RolePermissionRepo implementation
func (f *FakeRepo) AddRP(ctx context.Context, roleID, permID string) error {
	if f.rolePerms[roleID] == nil {
		f.rolePerms[roleID] = make(map[string]struct{})
	}
	f.rolePerms[roleID][permID] = struct{}{}
	return nil
}
func (f *FakeRepo) Remove(ctx context.Context, roleID, permID string) error {
	if m, ok := f.rolePerms[roleID]; ok {
		delete(m, permID)
	}
	return nil
}
func (f *FakeRepo) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	out := []string{}
	if m, ok := f.rolePerms[roleID]; ok {
		for pid := range m {
			out = append(out, pid)
		}
	}
	return out, nil
}

// UserRoleRepo implementation
func (f *FakeRepo) AddUR(ctx context.Context, userID, roleID string) error {
	if f.userRoles[userID] == nil {
		f.userRoles[userID] = make(map[string]struct{})
	}
	f.userRoles[userID][roleID] = struct{}{}
	return nil
}
func (f *FakeRepo) RemoveUR(ctx context.Context, userID, roleID string) error {
	if m, ok := f.userRoles[userID]; ok {
		delete(m, roleID)
	}
	return nil
}
func (f *FakeRepo) ListRoles(ctx context.Context, userID string) ([]string, error) {
	out := []string{}
	if m, ok := f.userRoles[userID]; ok {
		for rid := range m {
			out = append(out, rid)
		}
	}
	return out, nil
}

// --- Tests ---

func TestPermissionCRUD(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake}

	p := &Permission{ID: "perm1", Resource: "survey", Action: ActionCreate}
	// Create
	err := mgr.CreatePermission(ctx, p)
	if err != nil {
		t.Fatalf("CreatePermission failed: %v", err)
	}
	// Get
	got, err := mgr.GetPermission(ctx, "perm1")
	if err != nil {
		t.Fatalf("GetPermission failed: %v", err)
	}
	if got == nil || got.Resource != "survey" {
		t.Errorf("expected resource 'survey', got %v", got)
	}
	// Delete
	err = mgr.DeletePermission(ctx, "perm1")
	if err != nil {
		t.Fatalf("DeletePermission failed: %v", err)
	}
	got, err = mgr.GetPermission(ctx, "perm1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestRoleCRUD(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Roles: fake}

	r := &Role{ID: "role1", Name: "editor"}
	err := mgr.CreateRole(ctx, r)
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	got, err := mgr.GetRole(ctx, "role1")
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}
	if got == nil || got.Name != "editor" {
		t.Errorf("expected name 'editor', got %v", got)
	}
	err = mgr.DeleteRole(ctx, "role1")
	if err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}
	got, err = mgr.GetRole(ctx, "role1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Users: fake}

	u := &User{ID: "user1", Username: "alice"}
	err := mgr.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	got, err := mgr.GetUser(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if got == nil || got.Username != "alice" {
		t.Errorf("expected username 'alice', got %v", got)
	}
	err = mgr.DeleteUser(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	got, err = mgr.GetUser(ctx, "user1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestRolePermissionAndUserRole(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{RP: fake, UR: fake}

	// Assign permission to role
	err := mgr.AssignPermissionToRole(ctx, "role1", "perm1")
	if err != nil {
		t.Fatalf("AssignPermissionToRole failed: %v", err)
	}
	perms, err := mgr.ListPermissionsForRole(ctx, "role1")
	if err != nil {
		t.Fatalf("ListPermissionsForRole failed: %v", err)
	}
	if len(perms) != 1 || perms[0] != "perm1" {
		t.Errorf("expected perms [perm1], got %v", perms)
	}
	err = mgr.RemovePermissionFromRole(ctx, "role1", "perm1")
	if err != nil {
		t.Fatalf("RemovePermissionFromRole failed: %v", err)
	}
	perms, err = mgr.ListPermissionsForRole(ctx, "role1")
	if len(perms) != 0 {
		t.Errorf("expected no perms after removal, got %v", perms)
	}

	// Assign role to user
	err = mgr.AssignRoleToUser(ctx, "user1", "role1")
	if err != nil {
		t.Fatalf("AssignRoleToUser failed: %v", err)
	}
	rls, err := mgr.ListRolesForUser(ctx, "user1")
	if err != nil {
		t.Fatalf("ListRolesForUser failed: %v", err)
	}
	if len(rls) != 1 || rls[0] != "role1" {
		t.Errorf("expected roles [role1], got %v", rls)
	}
	err = mgr.UnassignRoleFromUser(ctx, "user1", "role1")
	if err != nil {
		t.Fatalf("UnassignRoleFromUser failed: %v", err)
	}
	rls, err = mgr.ListRolesForUser(ctx, "user1")
	if len(rls) != 0 {
		t.Errorf("expected no roles after unassign, got %v", rls)
	}
}

func TestCanWithWildcardAndExact(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}

	// Create two permissions: wildcard action and explicit delete
	pw := &Permission{ID: "permAll", Resource: "survey", Action: ActionAll}
	pd := &Permission{ID: "permD", Resource: "survey", Action: ActionDelete}
	mgr.CreatePermission(ctx, pw)
	mgr.CreatePermission(ctx, pd)

	// Create a role and assign both permissions
	r := &Role{ID: "role1"}
	fake.CreateRole(ctx, r)
	mgr.AssignPermissionToRole(ctx, "role1", "permAll")
	mgr.AssignPermissionToRole(ctx, "role1", "permD")

	// Assign role to user
	mgr.AssignRoleToUser(ctx, "user1", "role1")

	// Can delete? should be true via wildcard or explicit
	ok, err := mgr.Can(ctx, "user1", "survey", ActionDelete)
	if err != nil || !ok {
		t.Errorf("expected Can delete=true, got %v, err %v", ok, err)
	}

	// Can update? should be true via wildcard
	ok, err = mgr.Can(ctx, "user1", "survey", ActionUpdate)
	if err != nil || !ok {
		t.Errorf("expected Can update=true, got %v, err %v", ok, err)
	}

	// Can create? should be true
	ok, err = mgr.Can(ctx, "user1", "survey", ActionCreate)
	if err != nil || !ok {
		t.Errorf("expected Can create=true, got %v, err %v", ok, err)
	}

	// Remove wildcard action permission
	mgr.RemovePermissionFromRole(ctx, "role1", "permAll")

	// Now Can update should be false (only explicit delete remains)
	ok, err = mgr.Can(ctx, "user1", "survey", ActionUpdate)
	if err != nil {
		t.Fatalf("expected no error on Can, got %v", err)
	}
	if ok {
		t.Errorf("expected Can update=false after removing wildcard, got %v", ok)
	}
}

func TestCanResourceWildcard(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}

	// Create a permission with resource wildcard and specific action
	pr := &Permission{ID: "permRes", Resource: "survey.*.test", Action: ActionCreate}
	mgr.CreatePermission(ctx, pr)

	// Create a role, user and assign
	r := &Role{ID: "role1"}
	fake.CreateRole(ctx, r)
	mgr.AssignPermissionToRole(ctx, "role1", "permRes")
	mgr.AssignRoleToUser(ctx, "user1", "role1")

	// Should match single segment wildcard
	ok, err := mgr.Can(ctx, "user1", "survey.foo.test", ActionCreate)
	if err != nil || !ok {
		t.Errorf("expected Can resource wildcard match=true, got %v, err %v", ok, err)
	}

	// Should match multi-segment wildcard
	ok, err = mgr.Can(ctx, "user1", "survey.foo.bar.test", ActionCreate)
	if err != nil || !ok {
		t.Errorf("expected Can multi-segment wildcard match=true, got %v, err %v", ok, err)
	}

	// Should not match non-conforming resource
	ok, err = mgr.Can(ctx, "user1", "surveys.foo.test", ActionCreate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Errorf("expected Can resource wildcard match=false for non-match, got %v", ok)
	}
}

func TestCanGlobalResourceWildcard(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}

	// Permission with global resource wildcard and any action
	pg := &Permission{ID: "permGlob", Resource: "*", Action: ActionAll}
	mgr.CreatePermission(ctx, pg)

	// Setup role/user
	r := &Role{ID: "role1"}
	fake.CreateRole(ctx, r)
	mgr.AssignPermissionToRole(ctx, "role1", "permGlob")
	mgr.AssignRoleToUser(ctx, "user1", "role1")

	// Should match any resource/action
	ok, err := mgr.Can(ctx, "user1", "any.resource.name", ActionUpdate)
	if err != nil || !ok {
		t.Errorf("expected global resource wildcard match=true, got %v, err %v", ok, err)
	}
}
