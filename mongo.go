// file: rbac/mongo_store.go
package rbac

import (
	"context"
	"fmt"
	"time"

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
)

type MongoStore struct {
	permsCol    *mongo.Collection
	rolesCol    *mongo.Collection
	usersCol    *mongo.Collection
	rolePermCol *mongo.Collection
	userRoleCol *mongo.Collection
}

func NewMongoStore(db *mongo.Database) *MongoStore {
	return &MongoStore{
		permsCol:    db.Collection("permissions"),
		rolesCol:    db.Collection("roles"),
		usersCol:    db.Collection("users"),
		rolePermCol: db.Collection("role_permissions"),
		userRoleCol: db.Collection("user_roles"),
	}
}
func NewMongoStoreManager(db *mongo.Database) *Manager {
	m := NewMongoStore(db)
	return &Manager{
		Perms: m,
		Roles: m,
		Users: m,
		RP:    m,
		UR:    m,
	}

}

// --- PermissionRepo ---

func (m *MongoStore) CreatePermission(ctx context.Context, p *Permission) error {
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

// --- UserRepo ---

func (m *MongoStore) CreateUser(ctx context.Context, u *User) error {
	oid := primitive.NewObjectID()
	u.ID = oid.Hex()
	doc := bson.M{"_id": oid, "username": u.Username, "email": u.Email, "created_at": time.Now().Unix()}
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
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Username  string
		Email     string
		CreatedAt int64 `bson:"created_at"`
	}
	err = m.usersCol.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &User{ID: id, Username: doc.Username, Email: doc.Email, CreatedAt: doc.CreatedAt}, nil
}

// --- RolePermissionRepo ---

func (m *MongoStore) AddRP(ctx context.Context, roleID, permID string) error {
	rOID, _ := primitive.ObjectIDFromHex(roleID)
	pOID, _ := primitive.ObjectIDFromHex(permID)
	_, err := m.rolePermCol.InsertOne(ctx, bson.M{"role_id": rOID, "permission_id": pOID, "created_at": time.Now().Unix()})
	return err
}

func (m *MongoStore) Remove(ctx context.Context, roleID, permID string) error {
	rOID, _ := primitive.ObjectIDFromHex(roleID)
	pOID, _ := primitive.ObjectIDFromHex(permID)
	_, err := m.rolePermCol.DeleteOne(ctx, bson.M{"role_id": rOID, "permission_id": pOID})
	return err
}

func (m *MongoStore) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	rOID, _ := primitive.ObjectIDFromHex(roleID)
	cur, err := m.rolePermCol.Find(ctx, bson.M{"role_id": rOID})
	if err != nil {
		return nil, err
	}
	var out []string
	var rec struct {
		PermissionID primitive.ObjectID `bson:"permission_id"`
	}
	for cur.Next(ctx) {
		cur.Decode(&rec)
		out = append(out, rec.PermissionID.Hex())
	}
	return out, nil
}

// --- UserRoleRepo ---

func (m *MongoStore) AddUR(ctx context.Context, userID, roleID string) error {
	uOID, _ := primitive.ObjectIDFromHex(userID)
	rOID, _ := primitive.ObjectIDFromHex(roleID)
	_, err := m.userRoleCol.InsertOne(ctx, bson.M{"user_id": uOID, "role_id": rOID, "assigned_at": time.Now().Unix()})
	return err
}

func (m *MongoStore) RemoveUR(ctx context.Context, userID, roleID string) error {
	uOID, _ := primitive.ObjectIDFromHex(userID)
	rOID, _ := primitive.ObjectIDFromHex(roleID)
	_, err := m.userRoleCol.DeleteOne(ctx, bson.M{"user_id": uOID, "role_id": rOID})
	return err
}

func (m *MongoStore) ListRoles(ctx context.Context, userID string) ([]string, error) {
	uOID, _ := primitive.ObjectIDFromHex(userID)
	cur, err := m.userRoleCol.Find(ctx, bson.M{"user_id": uOID})
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
	return out, nil
}
