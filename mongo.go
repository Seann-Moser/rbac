// file: rbac/mongo_store.go
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//
// ---------- Helper Conversion ----------
//

//
// ---------- Mongo DB Models ----------
//

// Permissions

// Role → Permission mapping
type mongoRolePermission struct {
	RoleID       string `bson:"role_id"`
	PermissionID string `bson:"permission_id"`
	CreatedAt    int64  `bson:"created_at"`
}

// User → Role mapping
type mongoUserRole struct {
	UserID     string `bson:"user_id"`
	RoleID     string `bson:"role_id"`
	AssignedAt int64  `bson:"assigned_at"`
}

// Group → Role mapping
type mongoGroupRole struct {
	GroupName string `bson:"group_name"`
	RoleID    string `bson:"role_id"`
	CreatedAt int64  `bson:"created_at"` // Added for consistency, though not strictly required
}

// Ensure MongoStore implements all interfaces:
var (
	_ PermissionRepo     = (*MongoStore)(nil)
	_ RoleRepo           = (*MongoStore)(nil)
	_ UserRepo           = (*MongoStore)(nil)
	_ RolePermissionRepo = (*MongoStore)(nil)
	_ UserRoleRepo       = (*MongoStore)(nil)
	_ UserGroupRepo      = (*MongoStore)(nil)
	_ GroupRoleRepo      = (*MongoStore)(nil)
)

//
// ---------- MongoStore Core ----------
//

type MongoStore struct {
	permsCol     *mongo.Collection
	rolesCol     *mongo.Collection
	usersCol     *mongo.Collection
	rolePermCol  *mongo.Collection
	userRoleCol  *mongo.Collection
	userGroupCol *mongo.Collection
	groupRoleCol *mongo.Collection // unused if Option 1 (groups purely name-based)
}

func NewMongoStore(ctx context.Context, db *mongo.Database) (*MongoStore, error) {
	m := &MongoStore{
		permsCol:     db.Collection("permissions"),
		rolesCol:     db.Collection("roles"),
		usersCol:     db.Collection("users"),
		rolePermCol:  db.Collection("role_permissions"),
		userRoleCol:  db.Collection("user_roles"),
		userGroupCol: db.Collection("user_groups"),
		groupRoleCol: db.Collection("group_roles"), // Initialize groupRoleCol
	}

	if err := m.EnsureIndexes(ctx); err != nil {
		return nil, err
	}

	return m, nil
}

func NewMongoStoreManager(ctx context.Context, db *mongo.Database) (*Manager, error) {
	m, err := NewMongoStore(ctx, db)
	if err != nil {
		return nil, err
	}

	// Ensure default role exists
	def, _ := m.GetRoleByName(ctx, "default")
	if def == nil {
		def = &Role{Name: "default", Description: "Default role"}
		// Use a temporary role to get the ID back since CreateRole sets it
		if createErr := m.CreateRole(ctx, def); createErr != nil {
			return nil, fmt.Errorf("failed to create default role: %w", createErr)
		}
	}

	return &Manager{
		Perms:           m,
		Roles:           m,
		Users:           m,
		RP:              m,
		UR:              m,
		UG:              m,
		DefaultRoleName: "default",
	}, nil
}

// --- UserRepo ---

func (m *MongoStore) GetUserByMeta(ctx context.Context, meta map[string]interface{}) (*User, error) {
	var doc User
	err := m.usersCol.FindOne(ctx, meta).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

func (m *MongoStore) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	var doc Permission
	err := m.permsCol.FindOne(ctx, bson.M{"resource": resource, "action": string(action)}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

func (m *MongoStore) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {

	filter := bson.M{"user_id": userID}
	cur, err := m.userGroupCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []*UserGroup
	for cur.Next(ctx) {
		var doc UserGroup
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, &doc)
	}
	return out, cur.Err()
}

//
// ---------- Indexes ----------
//

func (m *MongoStore) EnsureIndexes(ctx context.Context) error {
	// Permissions: unique(resource, action)
	_, err := m.permsCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"resource", 1}, {"action", 1}}, //nolint:govet
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	// Roles: unique(name)
	_, err = m.rolesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"name", 1}}, //nolint:govet
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	// Users: unique(username), unique(email)
	for _, idx := range []mongo.IndexModel{
		{Keys: bson.D{{"username", 1}}, Options: options.Index().SetUnique(true)}, //nolint:govet
		{Keys: bson.D{{"email", 1}}, Options: options.Index().SetUnique(true)},    //nolint:govet
	} {
		if _, err = m.usersCol.Indexes().CreateOne(ctx, idx); err != nil {
			return err
		}
	}

	// Role permissions: unique(role_id, permission_id)
	_, err = m.rolePermCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"role_id", 1}, {"permission_id", 1}}, //nolint:govet
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	// User roles: unique(user_id, role_id)
	_, err = m.userRoleCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"user_id", 1}, {"role_id", 1}}, //nolint:govet
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	_, err = m.groupRoleCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"group_name", 1}, {"role_id", 1}}, //nolint:govet
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	return nil
}

// AddRoleToGroup stores a (groupID,roleID) pair
func (m *MongoStore) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	doc := mongoGroupRole{
		GroupName: groupID,
		RoleID:    roleID,
		CreatedAt: time.Now().Unix(),
	}
	_, err := m.groupRoleCol.InsertOne(ctx, doc)
	return err
}

// RemoveRoleFromGroup deletes that pairing
func (m *MongoStore) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	_, err := m.groupRoleCol.DeleteOne(ctx, bson.M{
		"group_name": groupID,
		"role_id":    roleID,
	})
	return err
}

// ListRolesForGroup returns all roleIDs for a given group
func (m *MongoStore) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	cur, err := m.groupRoleCol.Find(ctx, bson.M{"group_name": groupID})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cur.Close(ctx)
	}()

	var out []string
	for cur.Next(ctx) {
		var doc mongoGroupRole
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, doc.RoleID)
	}
	return out, cur.Err()
}

// --- PermissionRepo ---
func (m *MongoStore) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	var doc Permission
	err := m.permsCol.FindOne(ctx, bson.M{"id": id}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Use the Action enum directly on the Permission struct
	return &doc, nil
}

func (m *MongoStore) DeleteRole(ctx context.Context, id string) error {
	_, err := m.rolesCol.DeleteOne(ctx, bson.M{"id": id})
	return err
}

func (m *MongoStore) DeleteUser(ctx context.Context, id string) error {
	_, err := m.usersCol.DeleteOne(ctx, bson.M{"id": id})
	return err
}

func (m *MongoStore) ListAllRoles(ctx context.Context) (r []*Role, err error) {

	cur, err := m.rolesCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		var doc Role
		err = cur.Decode(&doc)
		if err != nil {
			return nil, fmt.Errorf("failed to decode role: %w", err)
		}
		r = append(r, &doc)
	}
	return r, cur.Err()
}

//
// ---------- Permissions ----------
//

func (m *MongoStore) CreatePermission(ctx context.Context, p *Permission) error {
	existing, _ := m.GetPermissionByResource(ctx, p.Resource, p.Action)
	if existing != nil {
		*p = *existing
		return nil
	}

	p.ID = uuid.New().String()
	p.CreatedAt = time.Now().Unix()

	_, err := m.permsCol.InsertOne(ctx, p)
	return err
}

func (m *MongoStore) DeletePermission(ctx context.Context, id string) error {
	_, err := m.permsCol.DeleteOne(ctx, bson.M{"id": id})
	return err
}

//
// ---------- Roles ----------
//

func (m *MongoStore) CreateRole(ctx context.Context, r *Role) error {
	r.ID = uuid.New().String()
	r.CreatedAt = time.Now().Unix()

	_, err := m.rolesCol.InsertOne(ctx, r)
	return err
}

func (m *MongoStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	var doc Role
	err := m.rolesCol.FindOne(ctx, bson.M{"name": name}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

func (m *MongoStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	var doc Role
	err := m.rolesCol.FindOne(ctx, bson.M{"id": id}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

//
// ---------- Users ----------
//

func (m *MongoStore) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	u.CreatedAt = time.Now().Unix()

	_, err := m.usersCol.InsertOne(ctx, u)
	return err
}

func (m *MongoStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	var doc User
	err := m.usersCol.FindOne(ctx, bson.M{"id": id}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

//
// ---------- RolePermissions ----------
//

func (m *MongoStore) AddRP(ctx context.Context, roleID, permID string) error {

	doc := mongoRolePermission{
		RoleID:       roleID,
		PermissionID: permID,
		CreatedAt:    time.Now().Unix(),
	}

	_, err := m.rolePermCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) Remove(ctx context.Context, roleID, permID string) error {
	_, err := m.rolePermCol.DeleteOne(ctx, bson.M{
		"role_id":       roleID,
		"permission_id": permID,
	})
	return err
}

func (m *MongoStore) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	cur, err := m.rolePermCol.Find(ctx, bson.M{"role_id": roleID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []string
	for cur.Next(ctx) {
		var rec mongoRolePermission
		if err := cur.Decode(&rec); err != nil {
			return nil, err
		}
		out = append(out, rec.PermissionID)
	}

	return out, nil
}

//
// ---------- UserRoles ----------
//

func (m *MongoStore) AddUR(ctx context.Context, userID, roleID string) error {
	_, err := m.userRoleCol.InsertOne(ctx, mongoUserRole{
		UserID:     userID,
		RoleID:     roleID,
		AssignedAt: time.Now().Unix(),
	})
	return err
}

func (m *MongoStore) RemoveUR(ctx context.Context, userID, roleID string) error {
	_, err := m.userRoleCol.DeleteOne(ctx, bson.M{
		"user_id": userID,
		"role_id": roleID,
	})
	return err
}

func (m *MongoStore) ListRoles(ctx context.Context, userID string) ([]string, error) {
	var out []string
	cur, err := m.userRoleCol.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		// always add default role
		if r, _ := m.GetRoleByName(ctx, "default"); r != nil {
			out = append(out, r.ID)
		}
		return out, err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		var rec mongoUserRole
		if err := cur.Decode(&rec); err != nil {
			return nil, err
		}
		out = append(out, rec.RoleID)
	}

	// always add default role
	if r, _ := m.GetRoleByName(ctx, "default"); r != nil {
		out = append(out, r.ID)
	}

	return out, nil
}

//
// ---------- User Groups (Option 1) ----------
//AddUserToGroup

func (m *MongoStore) AddUserToGroup(ctx context.Context, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	ug.ID = uuid.New().String()
	ug.CreatedAt = time.Now().Unix()

	_, err := m.userGroupCol.InsertOne(ctx, ug)
	return err
}

func (m *MongoStore) RemoveUserFromGroup(ctx context.Context, groupName string, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	_, err := m.userGroupCol.DeleteOne(ctx, bson.M{
		"user_id":    ug.UserID,
		"group_name": groupName,
	})
	return err
}

func (m *MongoStore) GetUsersByGroupID(ctx context.Context, groupName string) ([]*UserGroup, error) {
	cur, err := m.userGroupCol.Find(ctx, bson.M{"group_name": groupName})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []*UserGroup
	for cur.Next(ctx) {
		var doc UserGroup
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}

		out = append(out, &doc)
	}

	return out, cur.Err()
}
