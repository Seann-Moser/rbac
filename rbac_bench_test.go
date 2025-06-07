package rbac

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkCan_NoRoles measures performance when the user has no roles.
func BenchmarkCan_NoRoles(b *testing.B) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mgr.Can(ctx, "userX", "survey", ActionRead)
	}
}

// BenchmarkCan_SingleRoleSinglePerm measures performance with one role and one permission.
func BenchmarkCan_SingleRoleSinglePerm(b *testing.B) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}
	// setup one role, one perm
	fake.perms["perm1"] = &Permission{ID: "perm1", Resource: "survey", Action: ActionRead}
	fake.rolePerms["role1"] = map[string]struct{}{"perm1": {}}
	fake.userRoles["user1"] = map[string]struct{}{"role1": {}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mgr.Can(ctx, "user1", "survey", ActionRead)
	}
}

// BenchmarkCan_ManyRolesManyPerms measures performance with many roles and permissions.
func BenchmarkCan_ManyRolesManyPerms(b *testing.B) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}
	userID := "user1"
	rolesCount := 100
	permsPerRole := 50

	// setup many roles and perms
	for r := 0; r < rolesCount; r++ {
		roleID := fmt.Sprintf("role%03d", r)
		if fake.userRoles[userID] == nil {
			fake.userRoles[userID] = make(map[string]struct{})
		}
		fake.userRoles[userID][roleID] = struct{}{}
		fake.rolePerms[roleID] = make(map[string]struct{})
		for p := 0; p < permsPerRole; p++ {
			permID := fmt.Sprintf("perm%03d_%02d", r, p)
			fake.perms[permID] = &Permission{ID: permID, Resource: "survey", Action: ActionRead}
			fake.rolePerms[roleID][permID] = struct{}{}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mgr.Can(ctx, userID, "survey", ActionRead)
	}
}

// BenchmarkCan_ResourceWildcard measures performance of resource wildcard matching.
func BenchmarkCan_ResourceWildcard(b *testing.B) {
	ctx := context.Background()
	fake := NewFakeRepo()
	mgr := &Manager{Perms: fake, RP: fake, UR: fake}
	// setup wildcard perm
	fake.perms["permW"] = &Permission{ID: "permW", Resource: "survey.*.test", Action: ActionRead}
	fake.rolePerms["role1"] = map[string]struct{}{"permW": {}}
	fake.userRoles["user1"] = map[string]struct{}{"role1": {}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mgr.Can(ctx, "user1", "survey.some.test", ActionRead)
	}
}
