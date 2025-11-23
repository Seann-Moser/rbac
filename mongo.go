// file: rbac/mongo_store.go
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//
// ---------- Helper Conversion ----------
//

func oidToHex(oid primitive.ObjectID) string {
	return oid.Hex()
}

func hexToOID(id string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(id)
}

//
// ---------- Mongo DB Models ----------
//

// Permissions
type mongoPermission struct {
	ID        primitive.ObjectID `bson:"_id"`
	Resource  string             `bson:"resource"`
	Action    string             `bson:"action"`
	CreatedAt int64              `bson:"created_at"`
}

// Roles
type mongoRole struct {
	ID          primitive.ObjectID `bson:"_id"`
	Name        string             `bson:"name"`
	Description string             `bson:"description"`
	CreatedAt   int64              `bson:"created_at"`
}

// Users
type mongoUser struct {
	ID        primitive.ObjectID     `bson:"_id"`
	Username  string                 `bson:"username"`
	Email     string                 `bson:"email"`
	Meta      map[string]interface{} `bson:"meta"`
	CreatedAt int64                  `bson:"created_at"`
}

// User Groups
type mongoUserGroup struct {
	ID        primitive.ObjectID `bson:"_id"`
	UserID    primitive.ObjectID `bson:"user_id"`
	GroupName string             `bson:"group_name"`
	CreatedAt int64              `bson:"created_at"`
}

// Role → Permission mapping
type mongoRolePermission struct {
	RoleID       primitive.ObjectID `bson:"role_id"`
	PermissionID primitive.ObjectID `bson:"permission_id"`
	CreatedAt    int64              `bson:"created_at"`
}

// User → Role mapping
type mongoUserRole struct {
	UserID     primitive.ObjectID `bson:"user_id"`
	RoleID     primitive.ObjectID `bson:"role_id"`
	AssignedAt int64              `bson:"assigned_at"`
}

// Group → Role mapping
type mongoGroupRole struct {
	GroupName string `bson:"groupname"`
	RoleID    string `bson:"roleid"`
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
	var doc mongoUser
	err := m.usersCol.FindOne(ctx, meta).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &User{
		ID:        oidToHex(doc.ID),
		Username:  doc.Username,
		Email:     doc.Email,
		CreatedAt: doc.CreatedAt,
		Meta:      doc.Meta,
	}, nil
}

func (m *MongoStore) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	var doc mongoPermission
	err := m.permsCol.FindOne(ctx, bson.M{"resource": resource, "action": string(action)}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Permission{ID: doc.ID.Hex(), Resource: doc.Resource, Action: action, CreatedAt: doc.CreatedAt}, nil
}

func (m *MongoStore) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	uOID, err := hexToOID(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	filter := bson.M{"user_id": uOID}
	cur, err := m.userGroupCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []*UserGroup
	for cur.Next(ctx) {
		var doc mongoUserGroup
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, &UserGroup{
			ID:        doc.ID.Hex(),
			UserID:    doc.UserID.Hex(),
			GroupName: doc.GroupName,
			CreatedAt: doc.CreatedAt,
		})
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

	// Group roles: unique(groupname, roleid)
	_, err = m.groupRoleCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"groupname", 1}, {"roleid", 1}}, //nolint:govet
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	return nil
}

// AddRoleToGroup stores a (groupID,roleID) pair
func (m *MongoStore) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	// Note: RoleID is stored as a string, not ObjectID, for consistency with groupID
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
		"groupname": groupID,
		"roleid":    roleID,
	})
	return err
}

// ListRolesForGroup returns all roleIDs for a given group
func (m *MongoStore) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	cur, err := m.groupRoleCol.Find(ctx, bson.M{"groupname": groupID})
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
	oid, err := hexToOID(id)
	if err != nil {
		return nil, fmt.Errorf("invalid permission ID format: %w", err)
	}
	var doc mongoPermission
	err = m.permsCol.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Use the Action enum directly on the Permission struct
	return &Permission{ID: id, Resource: doc.Resource, Action: Action(doc.Action), CreatedAt: doc.CreatedAt}, nil
}

func (m *MongoStore) DeleteRole(ctx context.Context, id string) error {
	oid, err := hexToOID(id)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}
	_, err = m.rolesCol.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func (m *MongoStore) DeleteUser(ctx context.Context, id string) error {
	oid, err := hexToOID(id)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}
	_, err = m.usersCol.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func (m *MongoStore) ListAllRoles(ctx context.Context) (r []*Role, err error) {
	var doc struct {
		Id          primitive.ObjectID `bson:"_id"` // FIX: Use ObjectID for decoding
		Name        string
		Description string
		CreatedAt   int64 `bson:"created_at"`
	}

	cur, err := m.rolesCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		err = cur.Decode(&doc)
		if err != nil {
			return nil, fmt.Errorf("failed to decode role: %w", err)
		}
		r = append(r, &Role{
			ID:          oidToHex(doc.Id), // FIX: Convert ObjectID to hex string
			Name:        doc.Name,
			Description: doc.Description,
			CreatedAt:   doc.CreatedAt,
		})
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

	oid := primitive.NewObjectID()
	p.ID = oidToHex(oid)
	p.CreatedAt = time.Now().Unix()

	doc := mongoPermission{
		ID:        oid,
		Resource:  p.Resource,
		Action:    string(p.Action),
		CreatedAt: p.CreatedAt,
	}

	_, err := m.permsCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) DeletePermission(ctx context.Context, id string) error {
	oid, err := hexToOID(id)
	if err != nil {
		return fmt.Errorf("invalid permission ID format: %w", err)
	}

	_, err = m.permsCol.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

//
// ---------- Roles ----------
//

func (m *MongoStore) CreateRole(ctx context.Context, r *Role) error {
	oid := primitive.NewObjectID()
	r.ID = oid.Hex()
	r.CreatedAt = time.Now().Unix()

	doc := mongoRole{
		ID:          oid,
		Name:        r.Name,
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
	}

	_, err := m.rolesCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	var doc mongoRole
	err := m.rolesCol.FindOne(ctx, bson.M{"name": name}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &Role{
		ID:          oidToHex(doc.ID),
		Name:        doc.Name,
		Description: doc.Description,
		CreatedAt:   doc.CreatedAt,
	}, nil
}

func (m *MongoStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	oid, err := hexToOID(id)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID format: %w", err)
	}

	var doc mongoRole
	err = m.rolesCol.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &Role{
		ID:          id,
		Name:        doc.Name,
		Description: doc.Description,
		CreatedAt:   doc.CreatedAt,
	}, nil
}

//
// ---------- Users ----------
//

func (m *MongoStore) CreateUser(ctx context.Context, u *User) error {
	oid := primitive.NewObjectID()

	u.ID = oidToHex(oid)
	u.CreatedAt = time.Now().Unix()

	doc := mongoUser{
		ID:        oid,
		Username:  u.Username,
		Email:     u.Email,
		Meta:      u.Meta,
		CreatedAt: u.CreatedAt,
	}

	_, err := m.usersCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	oid, err := hexToOID(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err) // FIX: Provide context on ID conversion failure
	}

	var doc mongoUser
	err = m.usersCol.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &User{
		ID:        id,
		Username:  doc.Username,
		Email:     doc.Email,
		CreatedAt: doc.CreatedAt,
		Meta:      doc.Meta,
	}, nil
}

//
// ---------- RolePermissions ----------
//

func (m *MongoStore) AddRP(ctx context.Context, roleID, permID string) error {
	rOID, err := hexToOID(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	pOID, err := hexToOID(permID)
	if err != nil {
		return fmt.Errorf("invalid permission ID format: %w", err)
	}

	doc := mongoRolePermission{
		RoleID:       rOID,
		PermissionID: pOID,
		CreatedAt:    time.Now().Unix(),
	}

	_, err = m.rolePermCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) Remove(ctx context.Context, roleID, permID string) error {
	rOID, err := hexToOID(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	pOID, err := hexToOID(permID)
	if err != nil {
		return fmt.Errorf("invalid permission ID format: %w", err)
	}

	_, err = m.rolePermCol.DeleteOne(ctx, bson.M{
		"role_id":       rOID,
		"permission_id": pOID,
	})
	return err
}

func (m *MongoStore) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	rOID, err := hexToOID(roleID)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID format: %w", err)
	}

	cur, err := m.rolePermCol.Find(ctx, bson.M{"role_id": rOID})
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
		out = append(out, rec.PermissionID.Hex())
	}

	return out, nil
}

//
// ---------- UserRoles ----------
//

func (m *MongoStore) AddUR(ctx context.Context, userID, roleID string) error {
	uOID, err := hexToOID(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	rOID, err := hexToOID(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	_, err = m.userRoleCol.InsertOne(ctx, mongoUserRole{
		UserID:     uOID,
		RoleID:     rOID,
		AssignedAt: time.Now().Unix(),
	})
	return err
}

func (m *MongoStore) RemoveUR(ctx context.Context, userID, roleID string) error {
	uOID, err := hexToOID(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	rOID, err := hexToOID(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	_, err = m.userRoleCol.DeleteOne(ctx, bson.M{
		"user_id": uOID,
		"role_id": rOID,
	})
	return err
}

func (m *MongoStore) ListRoles(ctx context.Context, userID string) ([]string, error) {
	var out []string
	uOID, err := hexToOID(userID)
	if err != nil {
		// always add default role
		if r, _ := m.GetRoleByName(ctx, "default"); r != nil {
			out = append(out, r.ID)
		}
		return out, fmt.Errorf("invalid user ID format: %w", err)
	}

	cur, err := m.userRoleCol.Find(ctx, bson.M{"user_id": uOID})
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
		out = append(out, rec.RoleID.Hex())
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

	uOID, err := hexToOID(ug.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	oid := primitive.NewObjectID()
	ug.ID = oid.Hex()
	ug.CreatedAt = time.Now().Unix()

	doc := mongoUserGroup{
		ID:        oid,
		UserID:    uOID,
		GroupName: ug.GroupName,
		CreatedAt: ug.CreatedAt,
	}

	_, err = m.userGroupCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) RemoveUserFromGroup(ctx context.Context, groupName string, ug *UserGroup) error {
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}

	uOID, err := hexToOID(ug.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	_, err = m.userGroupCol.DeleteOne(ctx, bson.M{
		"user_id":    uOID,
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
		var doc mongoUserGroup
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}

		out = append(out, &UserGroup{
			ID:        doc.ID.Hex(),
			UserID:    doc.UserID.Hex(),
			GroupName: doc.GroupName,
			CreatedAt: doc.CreatedAt,
		})
	}

	return out, cur.Err()
}
