// file: rbac/store_test.go
package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// -----------------------------------------------------------------------
// storeAdapter is the union of all repo interfaces so the shared suite
// can call every method through a single value.
// -----------------------------------------------------------------------
type storeAdapter interface {
	PermissionRepo
	RoleRepo
	UserRepo
	RolePermissionRepo
	UserRoleRepo
	UserGroupRepo
	GroupRoleRepo
}

// -----------------------------------------------------------------------
// Container helpers
// -----------------------------------------------------------------------

func newPostgresStore(t *testing.T) storeAdapter {
	t.Helper()
	ctx := context.Background()

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("rbac_test"),
		postgres.WithUsername("rbac"),
		postgres.WithPassword("rbac"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	store, err := NewPostgresStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return store
}

func newMySQLStore(t *testing.T) storeAdapter {
	t.Helper()
	ctx := context.Background()

	ctr, err := mysql.Run(ctx, "mysql:8",
		mysql.WithDatabase("rbac_test"),
		mysql.WithUsername("rbac"),
		mysql.WithPassword("rbac"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("mysql host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "3306")
	if err != nil {
		t.Fatalf("mysql port: %v", err)
	}

	dsn := fmt.Sprintf("rbac:rbac@tcp(%s:%s)/rbac_test?parseTime=true", host, port.Port())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open mysql: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewMySQLStore(ctx, db)
	if err != nil {
		t.Fatalf("NewMySQLStore: %v", err)
	}
	return store
}

// -----------------------------------------------------------------------
// Shared test suite — called once for each store implementation
// -----------------------------------------------------------------------

func runSuite(t *testing.T, s storeAdapter) {
	t.Run("Permission", func(t *testing.T) { testPermissions(t, s) })
	t.Run("Role", func(t *testing.T) { testRoles(t, s) })
	t.Run("User", func(t *testing.T) { testUsers(t, s) })
	t.Run("RolePermission", func(t *testing.T) { testRolePermissions(t, s) })
	t.Run("UserRole", func(t *testing.T) { testUserRoles(t, s) })
	t.Run("UserGroup", func(t *testing.T) { testUserGroups(t, s) })
	t.Run("GroupRole", func(t *testing.T) { testGroupRoles(t, s) })
}

// -----------------------------------------------------------------------
// Top-level test functions — one per store
// -----------------------------------------------------------------------

func TestPostgresStore(t *testing.T) {
	runSuite(t, newPostgresStore(t))
}

func TestMySQLStore(t *testing.T) {
	runSuite(t, newMySQLStore(t))
}

// -----------------------------------------------------------------------
// Permission tests
// -----------------------------------------------------------------------

func testPermissions(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		p := &Permission{Resource: "articles", Action: ActionRead}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("CreatePermission: %v", err)
		}
		if p.ID == "" {
			t.Fatal("expected ID to be set after create")
		}

		got, err := s.GetPermissionByID(ctx, p.ID)
		if err != nil {
			t.Fatalf("GetPermissionByID: %v", err)
		}
		if got == nil {
			t.Fatal("expected permission, got nil")
		}
		if got.Resource != "articles" || got.Action != ActionRead {
			t.Errorf("unexpected permission: %+v", got)
		}
	})

	t.Run("GetByResource", func(t *testing.T) {
		p := &Permission{Resource: "posts", Action: ActionCreate}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("CreatePermission: %v", err)
		}

		got, err := s.GetPermissionByResource(ctx, "posts", ActionCreate)
		if err != nil {
			t.Fatalf("GetPermissionByResource: %v", err)
		}
		if got == nil || got.ID != p.ID {
			t.Errorf("expected permission %s, got %+v", p.ID, got)
		}
	})

	t.Run("CreateIdempotent", func(t *testing.T) {
		p1 := &Permission{Resource: "videos", Action: ActionDelete}
		if err := s.CreatePermission(ctx, p1); err != nil {
			t.Fatalf("first CreatePermission: %v", err)
		}

		// Second call with same resource+action should return the existing one.
		p2 := &Permission{Resource: "videos", Action: ActionDelete}
		if err := s.CreatePermission(ctx, p2); err != nil {
			t.Fatalf("second CreatePermission: %v", err)
		}
		if p1.ID != p2.ID {
			t.Errorf("expected same ID on duplicate create, got %s vs %s", p1.ID, p2.ID)
		}
	})

	t.Run("GetByIDNotFound", func(t *testing.T) {
		got, err := s.GetPermissionByID(ctx, "nonexistent-id")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		p := &Permission{Resource: "temp-resource", Action: ActionAll}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("CreatePermission: %v", err)
		}
		if err := s.DeletePermission(ctx, p.ID); err != nil {
			t.Fatalf("DeletePermission: %v", err)
		}

		got, err := s.GetPermissionByID(ctx, p.ID)
		if err != nil {
			t.Fatalf("GetPermissionByID after delete: %v", err)
		}
		if got != nil {
			t.Error("expected nil after delete")
		}
	})
}

// -----------------------------------------------------------------------
// Role tests
// -----------------------------------------------------------------------

func testRoles(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		r := &Role{Name: "admin", Description: "Administrator"}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if r.ID == "" {
			t.Fatal("expected ID to be set after create")
		}

		got, err := s.GetRoleByID(ctx, r.ID)
		if err != nil {
			t.Fatalf("GetRoleByID: %v", err)
		}
		if got == nil || got.Name != "admin" {
			t.Errorf("unexpected role: %+v", got)
		}
	})

	t.Run("GetByName", func(t *testing.T) {
		r := &Role{Name: "editor", Description: "Editor"}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}

		got, err := s.GetRoleByName(ctx, "editor")
		if err != nil {
			t.Fatalf("GetRoleByName: %v", err)
		}
		if got == nil || got.ID != r.ID {
			t.Errorf("expected role %s, got %+v", r.ID, got)
		}
	})

	t.Run("GetByNameNotFound", func(t *testing.T) {
		got, err := s.GetRoleByName(ctx, "nonexistent-role")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("ListAllRoles", func(t *testing.T) {
		// Create two more distinct roles for this sub-test.
		for _, name := range []string{"viewer", "moderator"} {
			if err := s.CreateRole(ctx, &Role{Name: name}); err != nil {
				t.Fatalf("CreateRole %s: %v", name, err)
			}
		}

		roles, err := s.ListAllRoles(ctx)
		if err != nil {
			t.Fatalf("ListAllRoles: %v", err)
		}
		if len(roles) < 2 {
			t.Errorf("expected at least 2 roles, got %d", len(roles))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		r := &Role{Name: "temp-role"}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if err := s.DeleteRole(ctx, r.ID); err != nil {
			t.Fatalf("DeleteRole: %v", err)
		}

		got, err := s.GetRoleByID(ctx, r.ID)
		if err != nil {
			t.Fatalf("GetRoleByID after delete: %v", err)
		}
		if got != nil {
			t.Error("expected nil after delete")
		}
	})
}

// -----------------------------------------------------------------------
// User tests
// -----------------------------------------------------------------------

func testUsers(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		u := &User{Username: "alice", Email: "alice@example.com"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.ID == "" {
			t.Fatal("expected ID to be set after create")
		}

		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if got == nil || got.Username != "alice" {
			t.Errorf("unexpected user: %+v", got)
		}
	})

	t.Run("GetByIDNotFound", func(t *testing.T) {
		got, err := s.GetUserByID(ctx, "nonexistent-id")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("GetByMeta_Username", func(t *testing.T) {
		u := &User{Username: "bob", Email: "bob@example.com"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		got, err := s.GetUserByMeta(ctx, map[string]interface{}{"username": "bob"})
		if err != nil {
			t.Fatalf("GetUserByMeta: %v", err)
		}
		if got == nil || got.ID != u.ID {
			t.Errorf("expected user %s, got %+v", u.ID, got)
		}
	})

	t.Run("GetByMeta_Email", func(t *testing.T) {
		u := &User{Username: "carol", Email: "carol@example.com"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		got, err := s.GetUserByMeta(ctx, map[string]interface{}{"email": "carol@example.com"})
		if err != nil {
			t.Fatalf("GetUserByMeta: %v", err)
		}
		if got == nil || got.ID != u.ID {
			t.Errorf("expected user %s, got %+v", u.ID, got)
		}
	})

	t.Run("GetByMeta_InvalidField", func(t *testing.T) {
		_, err := s.GetUserByMeta(ctx, map[string]interface{}{"bad_field": "x"})
		if err == nil {
			t.Error("expected error for unsupported meta field, got nil")
		}
	})

	t.Run("GetByMeta_NoFilter", func(t *testing.T) {
		_, err := s.GetUserByMeta(ctx, map[string]interface{}{})
		if err == nil {
			t.Error("expected error for empty meta filter, got nil")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		u := &User{Username: "temp-user", Email: "temp@example.com"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := s.DeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}

		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID after delete: %v", err)
		}
		if got != nil {
			t.Error("expected nil after delete")
		}
	})
}

// -----------------------------------------------------------------------
// RolePermission tests
// -----------------------------------------------------------------------

func testRolePermissions(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	role := &Role{Name: "rp-role"}
	if err := s.CreateRole(ctx, role); err != nil {
		t.Fatalf("setup CreateRole: %v", err)
	}
	perm := &Permission{Resource: "rp-resource", Action: ActionRead}
	if err := s.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("setup CreatePermission: %v", err)
	}

	t.Run("AddAndList", func(t *testing.T) {
		if err := s.AddRP(ctx, role.ID, perm.ID); err != nil {
			t.Fatalf("AddRP: %v", err)
		}

		ids, err := s.ListPermissions(ctx, role.ID)
		if err != nil {
			t.Fatalf("ListPermissions: %v", err)
		}
		if !containsStr(ids, perm.ID) {
			t.Errorf("expected perm %s in list %v", perm.ID, ids)
		}
	})

	t.Run("AddIdempotent", func(t *testing.T) {
		// Adding the same pair twice must not error.
		if err := s.AddRP(ctx, role.ID, perm.ID); err != nil {
			t.Errorf("duplicate AddRP should be idempotent, got: %v", err)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		if err := s.Remove(ctx, role.ID, perm.ID); err != nil {
			t.Fatalf("Remove: %v", err)
		}

		ids, err := s.ListPermissions(ctx, role.ID)
		if err != nil {
			t.Fatalf("ListPermissions after remove: %v", err)
		}
		if containsStr(ids, perm.ID) {
			t.Errorf("perm %s still in list after remove", perm.ID)
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		ids, err := s.ListPermissions(ctx, "nonexistent-role-id")
		if err != nil {
			t.Fatalf("ListPermissions on empty role: %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("expected empty list, got %v", ids)
		}
	})
}

// -----------------------------------------------------------------------
// UserRole tests
// -----------------------------------------------------------------------

func testUserRoles(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	user := &User{Username: "ur-user", Email: "ur-user@example.com"}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("setup CreateUser: %v", err)
	}
	role := &Role{Name: "ur-role"}
	if err := s.CreateRole(ctx, role); err != nil {
		t.Fatalf("setup CreateRole: %v", err)
	}

	// NewPostgresStore / NewMySQLStore do NOT seed a default role automatically;
	// only NewPostgresStoreManager / NewMySQLStoreManager do. So ListRoles
	// may or may not include "default" depending on how the store was created.
	// We just test the explicit assignment here.

	t.Run("AddAndList", func(t *testing.T) {
		if err := s.AddUR(ctx, user.ID, role.ID); err != nil {
			t.Fatalf("AddUR: %v", err)
		}

		ids, err := s.ListRoles(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListRoles: %v", err)
		}
		if !containsStr(ids, role.ID) {
			t.Errorf("expected role %s in list %v", role.ID, ids)
		}
	})

	t.Run("AddIdempotent", func(t *testing.T) {
		if err := s.AddUR(ctx, user.ID, role.ID); err != nil {
			t.Errorf("duplicate AddUR should be idempotent, got: %v", err)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		if err := s.RemoveUR(ctx, user.ID, role.ID); err != nil {
			t.Fatalf("RemoveUR: %v", err)
		}

		ids, err := s.ListRoles(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListRoles after remove: %v", err)
		}
		if containsStr(ids, role.ID) {
			t.Errorf("role %s still in list after remove", role.ID)
		}
	})
}

// -----------------------------------------------------------------------
// UserGroup tests
// -----------------------------------------------------------------------

func testUserGroups(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	user := &User{Username: "ug-user", Email: "ug-user@example.com"}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("setup CreateUser: %v", err)
	}

	t.Run("AddAndGetByUserID", func(t *testing.T) {
		ug := &UserGroup{UserID: user.ID, GroupName: "engineering"}
		if err := s.AddUserToGroup(ctx, ug); err != nil {
			t.Fatalf("AddUserToGroup: %v", err)
		}
		if ug.ID == "" {
			t.Fatal("expected ID to be set after add")
		}

		groups, err := s.GetGroupsByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetGroupsByUserID: %v", err)
		}
		if !containsGroup(groups, "engineering") {
			t.Errorf("expected group 'engineering' in %+v", groups)
		}
	})

	t.Run("GetUsersByGroupID", func(t *testing.T) {
		user2 := &User{Username: "ug-user2", Email: "ug-user2@example.com"}
		if err := s.CreateUser(ctx, user2); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		ug := &UserGroup{UserID: user2.ID, GroupName: "design"}
		if err := s.AddUserToGroup(ctx, ug); err != nil {
			t.Fatalf("AddUserToGroup: %v", err)
		}

		members, err := s.GetUsersByGroupID(ctx, "design")
		if err != nil {
			t.Fatalf("GetUsersByGroupID: %v", err)
		}
		if !containsUserID(members, user2.ID) {
			t.Errorf("expected user %s in group members %+v", user2.ID, members)
		}
	})

	t.Run("RemoveUserFromGroup", func(t *testing.T) {
		ug := &UserGroup{UserID: user.ID, GroupName: "temp-group"}
		if err := s.AddUserToGroup(ctx, ug); err != nil {
			t.Fatalf("AddUserToGroup: %v", err)
		}
		if err := s.RemoveUserFromGroup(ctx, "temp-group", ug); err != nil {
			t.Fatalf("RemoveUserFromGroup: %v", err)
		}

		groups, err := s.GetGroupsByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetGroupsByUserID after remove: %v", err)
		}
		if containsGroup(groups, "temp-group") {
			t.Error("expected group to be removed")
		}
	})

	t.Run("EmptyUserIDReturnsError", func(t *testing.T) {
		err := s.AddUserToGroup(ctx, &UserGroup{GroupName: "x"})
		if err == nil {
			t.Error("expected error for empty UserID, got nil")
		}
	})
}

// -----------------------------------------------------------------------
// GroupRole tests
// -----------------------------------------------------------------------

func testGroupRoles(t *testing.T, s storeAdapter) {
	ctx := context.Background()

	role := &Role{Name: "gr-role"}
	if err := s.CreateRole(ctx, role); err != nil {
		t.Fatalf("setup CreateRole: %v", err)
	}

	t.Run("AddAndList", func(t *testing.T) {
		if err := s.AddRoleToGroup(ctx, "ops", role.ID); err != nil {
			t.Fatalf("AddRoleToGroup: %v", err)
		}

		ids, err := s.ListRolesForGroup(ctx, "ops")
		if err != nil {
			t.Fatalf("ListRolesForGroup: %v", err)
		}
		if !containsStr(ids, role.ID) {
			t.Errorf("expected role %s in list %v", role.ID, ids)
		}
	})

	t.Run("AddIdempotent", func(t *testing.T) {
		if err := s.AddRoleToGroup(ctx, "ops", role.ID); err != nil {
			t.Errorf("duplicate AddRoleToGroup should be idempotent, got: %v", err)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		if err := s.RemoveRoleFromGroup(ctx, "ops", role.ID); err != nil {
			t.Fatalf("RemoveRoleFromGroup: %v", err)
		}

		ids, err := s.ListRolesForGroup(ctx, "ops")
		if err != nil {
			t.Fatalf("ListRolesForGroup after remove: %v", err)
		}
		if containsStr(ids, role.ID) {
			t.Errorf("role %s still in list after remove", role.ID)
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		ids, err := s.ListRolesForGroup(ctx, "nonexistent-group")
		if err != nil {
			t.Fatalf("ListRolesForGroup on empty group: %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("expected empty list, got %v", ids)
		}
	})
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func containsGroup(groups []*UserGroup, name string) bool {
	for _, g := range groups {
		if g.GroupName == name {
			return true
		}
	}
	return false
}

func containsUserID(groups []*UserGroup, userID string) bool {
	for _, g := range groups {
		if g.UserID == userID {
			return true
		}
	}
	return false
}
