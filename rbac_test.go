package rbac

import (
	"context"
	"testing"
)

// --- Tests ---

func TestPermissionCRUD(t *testing.T) {
	ctx := context.Background()
	fake := NewMockRepo()
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
	got, _ = mgr.GetPermission(ctx, "perm1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestRoleCRUD(t *testing.T) {
	ctx := context.Background()
	fake := NewMockRepo()
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
	got, _ = mgr.GetRole(ctx, "role1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	fake := NewMockRepo()
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
	got, _ = mgr.GetUser(ctx, "user1")
	if got != nil {
		t.Errorf("expected nil after delete, got %v", got)
	}
}

func TestRolePermissionAndUserRole(t *testing.T) {
	ctx := context.Background()
	fake := NewMockRepo()
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
	perms, _ = mgr.ListPermissionsForRole(ctx, "role1")
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
	rls, _ = mgr.ListRolesForUser(ctx, "user1")
	if len(rls) != 0 {
		t.Errorf("expected no roles after unassign, got %v", rls)
	}
}

func TestCanWithWildcardAndExact(t *testing.T) {
	ctx := context.Background()
	fake := NewMockRepo()
	mgr := NewMockRepoManager(fake)

	// Create two permissions: wildcard action and explicit delete
	pw := &Permission{ID: "permAll", Resource: "survey", Action: ActionAll}
	pd := &Permission{ID: "permD", Resource: "survey", Action: ActionDelete}
	_ = mgr.CreatePermission(ctx, pw)
	_ = mgr.CreatePermission(ctx, pd)

	// Create a role and assign both permissions
	r := &Role{ID: "role1"}
	_ = fake.CreateRole(ctx, r)
	_ = mgr.AssignPermissionToRole(ctx, "role1", "permAll")
	_ = mgr.AssignPermissionToRole(ctx, "role1", "permD")

	// Assign role to user
	_ = mgr.AssignRoleToUser(ctx, "user1", "role1")

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
	_ = mgr.RemovePermissionFromRole(ctx, "role1", "permAll")

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
	fake := NewMockRepo()
	mgr := NewMockRepoManager(fake)

	// Create a permission with resource wildcard and specific action
	pr := &Permission{ID: "permRes", Resource: "survey.*.test", Action: ActionCreate}
	_ = mgr.CreatePermission(ctx, pr)

	// Create a role, user and assign
	r := &Role{ID: "role1"}
	_ = fake.CreateRole(ctx, r)
	_ = mgr.AssignPermissionToRole(ctx, "role1", "permRes")
	_ = mgr.AssignRoleToUser(ctx, "user1", "role1")

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
	fake := NewMockRepo()
	mgr := NewMockRepoManager(fake)

	// Permission with global resource wildcard and any action
	pg := &Permission{ID: "permGlob", Resource: "*", Action: ActionAll}
	_ = mgr.CreatePermission(ctx, pg)

	// Setup role/user
	r := &Role{ID: "role1"}
	_ = fake.CreateRole(ctx, r)
	_ = mgr.AssignPermissionToRole(ctx, "role1", "permGlob")
	_ = mgr.AssignRoleToUser(ctx, "user1", "role1")

	// Should match any resource/action
	ok, err := mgr.Can(ctx, "user1", "any.resource.name", ActionUpdate)
	if err != nil || !ok {
		t.Errorf("expected global resource wildcard match=true, got %v, err %v", ok, err)
	}
}
