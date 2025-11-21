// file: rbac/mongo_store.go
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

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

type MongoStore struct {
	permsCol     *mongo.Collection
	rolesCol     *mongo.Collection
	usersCol     *mongo.Collection
	rolePermCol  *mongo.Collection
	userRoleCol  *mongo.Collection
	userGroupCol *mongo.Collection
	groupRoleCol *mongo.Collection
}

func (m *MongoStore) GetUserByMeta(ctx context.Context, meta map[string]interface{}) (*User, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MongoStore) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	var doc struct {
		Id        primitive.ObjectID `bson:"_id"`
		Resource  string
		Action    Action
		CreatedAt int64 `bson:"created_at"`
	}
	err := m.permsCol.FindOne(ctx, bson.M{"resource": resource, "action": string(action)}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &Permission{ID: doc.Id.Hex(), Resource: doc.Resource, Action: doc.Action, CreatedAt: doc.CreatedAt}, nil
}

// NewMongoStore creates the store and ensures all indexes exist.
func NewMongoStore(ctx context.Context, db *mongo.Database) (*MongoStore, error) {
	m := &MongoStore{
		permsCol:     db.Collection("permissions"),
		rolesCol:     db.Collection("roles"),
		usersCol:     db.Collection("users"),
		rolePermCol:  db.Collection("role_permissions"),
		userRoleCol:  db.Collection("user_roles"),
		userGroupCol: db.Collection("user_groups"),
		groupRoleCol: db.Collection("group_roles"),
	}
	if err := m.EnsureIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}
	return m, nil
}

// NewMongoStoreManager wires up the Manager, ensuring indexes too.
func NewMongoStoreManager(ctx context.Context, db *mongo.Database) (*Manager, error) {
	m, err := NewMongoStore(ctx, db)
	if err != nil {
		return nil, err
	}

	defaultRole, _ := m.GetRoleByName(ctx, "default")
	if defaultRole == nil {
		defaultRole = &Role{Name: "default"}
		err = m.CreateRole(ctx, defaultRole)
		if err != nil {
			return nil, err
		}
	}
	return &Manager{
		Perms:           m,
		Roles:           m,
		Users:           m,
		RP:              m,
		UR:              m,
		UG:              m,
		GR:              m,
		DefaultRoleName: "default",
	}, nil
}

func (m *MongoStore) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	filter := bson.M{"userid": userID}
	cur, err := m.userGroupCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cur.Close(ctx)
	}()

	var out []*UserGroup
	for cur.Next(ctx) {
		var ug UserGroup
		if err := cur.Decode(&ug); err != nil {
			return nil, err
		}
		out = append(out, &ug)
	}
	return out, cur.Err()
}

// AddRoleToGroup stores a (groupID,roleID) pair
func (m *MongoStore) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	_, err := m.groupRoleCol.InsertOne(ctx, bson.M{
		"groupname": groupID,
		"roleid":    roleID,
	})
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
		var doc struct {
			RoleID string `bson:"roleid"`
		}
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, doc.RoleID)
	}
	return out, cur.Err()
}

// EnsureIndexes makes sure each collection has the proper unique indexes.
func (m *MongoStore) EnsureIndexes(ctx context.Context) error {
	// permissions: unique on (resource, action)
	permIdx := mongo.IndexModel{
		Keys:    bson.D{{Key: "resource", Value: 1}, {Key: "action", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := m.permsCol.Indexes().CreateOne(ctx, permIdx); err != nil {
		return err
	}

	// roles: unique on name
	roleIdx := mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := m.rolesCol.Indexes().CreateOne(ctx, roleIdx); err != nil {
		return err
	}

	// users: unique on username, unique on email
	userIdx1 := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := m.usersCol.Indexes().CreateOne(ctx, userIdx1); err != nil {
		return err
	}
	userIdx2 := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := m.usersCol.Indexes().CreateOne(ctx, userIdx2); err != nil {
		return err
	}

	// role_permissions: unique on (role_id, permission_id)
	rpIdx := mongo.IndexModel{
		Keys:    bson.D{{Key: "role_id", Value: 1}, {Key: "permission_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := m.rolePermCol.Indexes().CreateOne(ctx, rpIdx); err != nil {
		return err
	}

	// user_roles: unique on (user_id, role_id)
	urIdx := mongo.IndexModel{
		Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "role_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	if _, err := m.userRoleCol.Indexes().CreateOne(ctx, urIdx); err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) AddUserToGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	// assign an object ID and timestamp
	if groupID == "" {
		ug.ID = primitive.NewObjectID().Hex()
	} else {
		ug.ID = groupID
	}
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}
	if ug.GroupName == "" {
		return errors.New("group name is empty")
	}
	ug.CreatedAt = time.Now().Unix()
	_, err := m.userGroupCol.InsertOne(ctx, ug)
	return err
}

func (m *MongoStore) RemoveUserFromGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	if groupID == "" {
		return errors.New("group id is empty")
	}
	if ug.UserID == "" {
		return errors.New("user id is empty")
	}
	filter := bson.M{
		"id":     groupID,
		"userid": ug.UserID,
	}
	_, err := m.userGroupCol.DeleteOne(ctx, filter)
	return err
}

func (m *MongoStore) GetUsersByGroupID(ctx context.Context, groupID string) ([]*UserGroup, error) {
	if groupID == "" {
		return nil, errors.New("group id is empty")
	}
	filter := bson.M{"id": groupID}
	cur, err := m.userGroupCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cur.Close(ctx)
	}()

	var results []*UserGroup
	for cur.Next(ctx) {
		var ug UserGroup
		if err := cur.Decode(&ug); err != nil {
			return nil, err
		}
		results = append(results, &ug)
	}
	return results, cur.Err()
}

// --- PermissionRepo ---

func (m *MongoStore) CreatePermission(ctx context.Context, p *Permission) error {
	tmp, _ := m.GetPermissionByResource(ctx, p.Resource, p.Action)
	if tmp != nil {
		p.ID = tmp.ID
		p.CreatedAt = tmp.CreatedAt
		return nil
	}
	oid := primitive.NewObjectID()
	p.ID = oid.Hex()

	doc := bson.M{"_id": oid, "resource": p.Resource, "action": p.Action, "created_at": time.Now().Unix()}
	_, err := m.permsCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) DeletePermission(ctx context.Context, id string) error {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	_, err = m.permsCol.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func (m *MongoStore) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Resource  string
		Action    Action
		CreatedAt int64 `bson:"created_at"`
	}
	err = m.permsCol.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &Permission{ID: id, Resource: doc.Resource, Action: doc.Action, CreatedAt: doc.CreatedAt}, nil
}

// --- RoleRepo ---

func (m *MongoStore) CreateRole(ctx context.Context, r *Role) error {
	oid := primitive.NewObjectID()
	r.ID = oid.Hex()
	doc := bson.M{"_id": oid, "name": r.Name, "description": r.Description, "created_at": time.Now().Unix()}
	_, err := m.rolesCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) DeleteRole(ctx context.Context, id string) error {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	_, err = m.rolesCol.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func (m *MongoStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Name        string
		Description string
		CreatedAt   int64 `bson:"created_at"`
	}
	err = m.rolesCol.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &Role{ID: id, Name: doc.Name, Description: doc.Description, CreatedAt: doc.CreatedAt}, nil
}

func (m *MongoStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	var doc struct {
		Id          string `bson:"_id"`
		Name        string
		Description string
		CreatedAt   int64 `bson:"created_at"`
	}
	err := m.rolesCol.FindOne(ctx, bson.M{"name": name}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &Role{ID: doc.Id, Name: doc.Name, Description: doc.Description, CreatedAt: doc.CreatedAt}, nil
}

// --- UserRepo ---

func (m *MongoStore) CreateUser(ctx context.Context, u *User) error {
	oid := primitive.NewObjectID()
	u.ID = oid.Hex()
	doc := bson.M{"_id": oid, "username": u.Username, "email": u.Email, "created_at": time.Now().Unix(), "meta": u.Meta}
	_, err := m.usersCol.InsertOne(ctx, doc)
	return err
}

func (m *MongoStore) DeleteUser(ctx context.Context, id string) error {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	_, err = m.usersCol.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func (m *MongoStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	var doc struct {
		Username  string
		Email     string
		Meta      map[string]interface{}
		CreatedAt int64 `bson:"created_at"`
	}
	err := m.usersCol.FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &User{ID: id, Username: doc.Username, Email: doc.Email, CreatedAt: doc.CreatedAt, Meta: doc.Meta}, nil
}

func (m *MongoStore) AddRP(ctx context.Context, roleID, permID string) error {
	rOID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return err
	}
	pOID, err := primitive.ObjectIDFromHex(permID)
	if err != nil {
		return err
	}
	_, err = m.rolePermCol.InsertOne(ctx, bson.M{"role_id": rOID, "permission_id": pOID, "created_at": time.Now().Unix()})
	return err
}

func (m *MongoStore) Remove(ctx context.Context, roleID, permID string) error {
	rOID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return err
	}
	pOID, err := primitive.ObjectIDFromHex(permID)
	if err != nil {
		return err
	}
	_, err = m.rolePermCol.DeleteOne(ctx, bson.M{"role_id": rOID, "permission_id": pOID})
	return err
}

func (m *MongoStore) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	rOID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return nil, err
	}
	cur, err := m.rolePermCol.Find(ctx, bson.M{"role_id": rOID})
	if err != nil {
		return nil, err
	}
	var out []string
	var rec struct {
		PermissionID primitive.ObjectID `bson:"permission_id"`
	}
	for cur.Next(ctx) {
		err = cur.Decode(&rec)
		if err != nil {
			return nil, err
		}
		out = append(out, rec.PermissionID.Hex())
	}
	return out, nil
}

// --- UserRoleRepo ---

func (m *MongoStore) AddUR(ctx context.Context, userID, roleID string) error {
	rOID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return err
	}
	_, err = m.userRoleCol.InsertOne(ctx, bson.M{"user_id": userID, "role_id": rOID, "assigned_at": time.Now().Unix()})
	return err
}

func (m *MongoStore) RemoveUR(ctx context.Context, userID, roleID string) error {
	rOID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return err
	}
	_, err = m.userRoleCol.DeleteOne(ctx, bson.M{"user_id": userID, "role_id": rOID})
	return err
}

func (m *MongoStore) ListRoles(ctx context.Context, userID string) ([]string, error) {
	cur, err := m.userRoleCol.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	var out []string
	var rec struct {
		RoleID primitive.ObjectID `bson:"role_id"`
	}
	for cur.Next(ctx) {
		err = cur.Decode(&rec)
		if err != nil {
			return nil, fmt.Errorf("failed to decode role ID")
		}
		out = append(out, rec.RoleID.Hex())
	}
	r, _ := m.GetRoleByName(ctx, "default")
	if r != nil {
		out = append(out, r.ID)
	}
	return out, nil
}

func (m *MongoStore) ListAllRoles(ctx context.Context) (r []*Role, err error) {
	var doc struct {
		Id          string `bson:"_id"`
		Name        string
		Description string
		CreatedAt   int64 `bson:"created_at"`
	}

	cur, err := m.rolesCol.Find(ctx, bson.M{})
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	for cur.Next(ctx) {
		err = cur.Decode(&doc)
		if err != nil {
			return nil, fmt.Errorf("failed to decode role")
		}
		r = append(r, &Role{ID: doc.Id, Name: doc.Name, Description: doc.Description, CreatedAt: doc.CreatedAt})
	}
	return r, nil
}
