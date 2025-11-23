package rbac_test

import (
	"context"
	"testing"

	"github.com/Seann-Moser/rbac"
	"github.com/stretchr/testify/require"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Start MongoDB in a container for each test
func startMongo(t *testing.T) (*mongo.Database, func()) {
	ctx := context.Background()

	mongoC, err := mongodb.RunContainer(ctx, //nolint:staticcheck
		testcontainers.WithImage("mongo:7"),
	)
	require.NoError(t, err)

	uri, err := mongoC.ConnectionString(ctx)
	require.NoError(t, err)

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	require.NoError(t, err)

	db := client.Database("testdb")

	cleanup := func() {
		_ = client.Disconnect(ctx)
		_ = mongoC.Terminate(ctx)
	}

	return db, cleanup
}

//
// ────────────────────────────────────────────────
//   USERS
// ────────────────────────────────────────────────
//

func TestCreateUserAndFetch(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	store, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	// Create user
	u := &rbac.User{
		Username: "alice",
		Email:    "alice@example.com",
		Meta:     map[string]interface{}{"level": "premium"},
	}
	err = store.Users.CreateUser(ctx, u)
	require.NoError(t, err)
	require.NotEmpty(t, u.ID)

	// Fetch back
	got, err := store.Users.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "alice", got.Username)
	require.Equal(t, "alice@example.com", got.Email)
	require.Equal(t, "premium", got.Meta["level"])
}

//
// ────────────────────────────────────────────────
//   ROLES
// ────────────────────────────────────────────────
//

func TestCreateRoleAndFetch(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	store, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	r := &rbac.Role{Name: "admin", Description: "full access"}
	err = store.Roles.CreateRole(ctx, r)
	require.NoError(t, err)

	got, err := store.Roles.GetRoleByID(ctx, r.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "admin", got.Name)
}

//
// ────────────────────────────────────────────────
//   USER → ROLE ASSIGNMENT
// ────────────────────────────────────────────────
//

func TestUserRoleAssignment(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	manager, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	// Create user
	user := &rbac.User{
		Username: "bob",
		Email:    "bob@example.com",
	}
	require.NoError(t, manager.Users.CreateUser(ctx, user))

	// Create role
	role := &rbac.Role{Name: "moderator"}
	require.NoError(t, manager.Roles.CreateRole(ctx, role))

	// Assign
	require.NoError(t, manager.UR.AddUR(ctx, user.ID, role.ID))

	roles, err := manager.UR.ListRoles(ctx, user.ID)
	require.NoError(t, err)

	require.Contains(t, roles, role.ID)
}

//
// ────────────────────────────────────────────────
//   PERMISSIONS
// ────────────────────────────────────────────────
//

func TestPermissionsFlow(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	manager, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	// Create permission
	p := &rbac.Permission{
		Resource: "posts",
		Action:   rbac.ActionCreate,
	}
	require.NoError(t, manager.Perms.CreatePermission(ctx, p))

	require.NotEmpty(t, p.ID)

	// Create Role
	role := &rbac.Role{Name: "editor"}
	require.NoError(t, manager.Roles.CreateRole(ctx, role))

	// Add permission to role
	require.NoError(t, manager.RP.AddRP(ctx, role.ID, p.ID))

	perms, err := manager.RP.ListPermissions(ctx, role.ID)
	require.NoError(t, err)
	require.Equal(t, []string{p.ID}, perms)
}

//
// ────────────────────────────────────────────────
//   USER GROUPS
// ────────────────────────────────────────────────
//

func TestUserGroups(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	manager, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	// user
	user := &rbac.User{Username: "eve", Email: "eve@example.com"}
	require.NoError(t, manager.Users.CreateUser(ctx, user))

	// Add user to group
	ug := &rbac.UserGroup{
		UserID:    user.ID,
		GroupName: "team-alpha",
	}

	require.NoError(t, manager.UG.AddUserToGroup(ctx, ug))

	groups, err := manager.UG.GetGroupsByUserID(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, ug.GroupName, groups[0].GroupName)
}

//
// ────────────────────────────────────────────────
//   UNIQUE INDEX ENFORCEMENT
// ────────────────────────────────────────────────
//

func TestUniqueIndexes_UserRoles(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	mgr, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	// user
	u := &rbac.User{Username: "kali", Email: "k@example.com"}
	require.NoError(t, mgr.Users.CreateUser(ctx, u))

	// role
	r := &rbac.Role{Name: "tester"}
	require.NoError(t, mgr.Roles.CreateRole(ctx, r))

	// 1st assignment → success
	require.NoError(t, mgr.UR.AddUR(ctx, u.ID, r.ID))

	// 2nd assignment → must fail due to unique index
	err = mgr.UR.AddUR(ctx, u.ID, r.ID)
	require.Error(t, err)
}

//
// ────────────────────────────────────────────────
//   DEFAULT ROLE CREATION
// ────────────────────────────────────────────────
//

func TestDefaultRoleInitialization(t *testing.T) {
	db, cleanup := startMongo(t)
	defer cleanup()

	ctx := context.Background()
	manager, err := rbac.NewMongoStoreManager(ctx, db)
	require.NoError(t, err)

	// default role must exist
	def, err := manager.Roles.GetRoleByName(ctx, "default")
	require.NoError(t, err)
	require.NotNil(t, def)
}
