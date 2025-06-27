package rbac

import (
	"context"
	"path"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter           = otel.Meter("rbac/manager")
	requestCounter  metric.Int64Counter
	errorCounter    metric.Int64Counter
	latencyRecorder metric.Float64Histogram
)

func init() {
	// Total number of calls to any Manager method
	requestCounter, _ = meter.Int64Counter(
		"rbac_manager_requests_total",
		metric.WithDescription("Total number of RBAC manager method invocations"),
	)
	// Total number of errors returned by Manager methods
	errorCounter, _ = meter.Int64Counter(
		"rbac_manager_errors_total",
		metric.WithDescription("Total number of errors in RBAC manager methods"),
	)
	// Distribution of method latencies (seconds)
	latencyRecorder, _ = meter.Float64Histogram(
		"rbac_manager_request_duration_seconds",
		metric.WithDescription("Latency of RBAC manager methods"),
	)
}

type Manager struct {
	Perms           PermissionRepo
	Roles           RoleRepo
	Users           UserRepo
	RP              RolePermissionRepo
	UR              UserRoleRepo
	UG              UserGroupRepo
	GR              GroupRoleRepo
	DefaultRoleName string
}

func (m *Manager) AssignRoleToGroup(ctx context.Context, groupID, roleID string) error {
	start := time.Now()
	err := m.GR.AddRoleToGroup(ctx, groupID, roleID)
	m.record(ctx, start, "AssignRoleToGroup", err)
	return err
}

func (m *Manager) UnassignRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	start := time.Now()
	err := m.GR.RemoveRoleFromGroup(ctx, groupID, roleID)
	m.record(ctx, start, "UnassignRoleFromGroup", err)
	return err
}

func (m *Manager) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	start := time.Now()
	roles, err := m.GR.ListRolesForGroup(ctx, groupID)
	m.record(ctx, start, "ListRolesForGroup", err)
	return roles, err
}

// CreateRole instruments the CreateRole call.
func (m *Manager) CreateRole(ctx context.Context, r *Role) error {
	start := time.Now()
	err := m.Roles.CreateRole(ctx, r)
	m.record(ctx, start, "CreateRole", err)
	return err
}

func (m *Manager) DeleteRole(ctx context.Context, id string) error {
	start := time.Now()
	err := m.Roles.DeleteRole(ctx, id)
	m.record(ctx, start, "DeleteRole", err)
	return err
}

func (m *Manager) GetRole(ctx context.Context, id string) (*Role, error) {
	start := time.Now()
	role, err := m.Roles.GetRoleByID(ctx, id)
	m.record(ctx, start, "GetRole", err)
	return role, err
}

func (m *Manager) CreateUser(ctx context.Context, u *User) error {
	start := time.Now()
	err := m.Users.CreateUser(ctx, u)
	m.record(ctx, start, "CreateUser", err)
	return err
}

func (m *Manager) DeleteUser(ctx context.Context, id string) error {
	start := time.Now()
	err := m.Users.DeleteUser(ctx, id)
	m.record(ctx, start, "DeleteUser", err)
	return err
}

func (m *Manager) GetUser(ctx context.Context, id string) (*User, error) {
	start := time.Now()
	user, err := m.Users.GetUserByID(ctx, id)
	m.record(ctx, start, "GetUser", err)
	return user, err
}

func (m *Manager) AssignPermissionToRole(ctx context.Context, roleID, permID string) error {
	start := time.Now()
	err := m.RP.AddRP(ctx, roleID, permID)
	m.record(ctx, start, "AssignPermissionToRole", err)
	return err
}

func (m *Manager) RemovePermissionFromRole(ctx context.Context, roleID, permID string) error {
	start := time.Now()
	err := m.RP.Remove(ctx, roleID, permID)
	m.record(ctx, start, "RemovePermissionFromRole", err)
	return err
}

func (m *Manager) ListPermissionsForRole(ctx context.Context, roleID string) ([]string, error) {
	start := time.Now()
	perms, err := m.RP.ListPermissions(ctx, roleID)
	m.record(ctx, start, "ListPermissionsForRole", err)
	return perms, err
}

func (m *Manager) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	start := time.Now()
	err := m.UR.AddUR(ctx, userID, roleID)
	m.record(ctx, start, "AssignRoleToUser", err)
	return err
}

func (m *Manager) UnassignRoleFromUser(ctx context.Context, userID, roleID string) error {
	start := time.Now()
	err := m.UR.RemoveUR(ctx, userID, roleID)
	m.record(ctx, start, "UnassignRoleFromUser", err)
	return err
}

func (m *Manager) ListRolesForUser(ctx context.Context, userID string) ([]string, error) {
	start := time.Now()
	roles, err := m.UR.ListRoles(ctx, userID)
	m.record(ctx, start, "ListRolesForUser", err)
	return roles, err
}

func (m *Manager) AddUserToGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	start := time.Now()
	err := m.UG.AddUserToGroup(ctx, groupID, ug)
	m.record(ctx, start, "AddUserToGroup", err)
	return err
}

func (m *Manager) RemoveUserFromGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	start := time.Now()
	err := m.UG.RemoveUserFromGroup(ctx, groupID, ug)
	m.record(ctx, start, "RemoveUserFromGroup", err)
	return err
}

func (m *Manager) GetUsersByGroupID(ctx context.Context, groupID string) ([]*UserGroup, error) {
	start := time.Now()
	list, err := m.UG.GetUsersByGroupID(ctx, groupID)
	m.record(ctx, start, "GetUsersByGroupID", err)
	return list, err
}

// CreatePermission instruments the underlying repo call.
func (m *Manager) CreatePermission(ctx context.Context, p *Permission) error {
	start := time.Now()
	err := m.Perms.CreatePermission(ctx, p)

	// common attributes
	attrs := []attribute.KeyValue{
		attribute.String("method", "CreatePermission"),
	}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return err
}

func (m *Manager) record(ctx context.Context, start time.Time, method string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
	}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

func (m *Manager) DeletePermission(ctx context.Context, id string) error {
	start := time.Now()
	err := m.Perms.DeletePermission(ctx, id)
	attrs := []attribute.KeyValue{attribute.String("method", "DeletePermission")}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return err
}

func (m *Manager) GetPermission(ctx context.Context, id string) (*Permission, error) {
	start := time.Now()
	perm, err := m.Perms.GetPermissionByID(ctx, id)
	attrs := []attribute.KeyValue{attribute.String("method", "GetPermission")}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return perm, err
}

// ... repeat the same wrapping for CreateRole, DeleteRole, GetRole, etc. ...

func (m *Manager) HasPermission(ctx context.Context, userID, permID string) (bool, error) {
	start := time.Now()
	ok, err := func() (bool, error) {
		roles, err := m.UR.ListRoles(ctx, userID)
		if err != nil {
			return false, err
		}
		for _, r := range roles {
			perms, err := m.RP.ListPermissions(ctx, r)
			if err != nil {
				return false, err
			}
			for _, p := range perms {
				if p == permID {
					return true, nil
				}
			}
		}
		return false, nil
	}()

	attrs := []attribute.KeyValue{attribute.String("method", "HasPermission")}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return ok, err
}

func (m *Manager) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	start := time.Now()
	groups, err := m.UG.GetGroupsByUserID(ctx, userID)
	m.record(ctx, start, "GetGroupsByUserID", err)
	return groups, err
}

// manager.go (update)
func (m *Manager) Can(ctx context.Context, userID, resource string, action Action) (bool, error) {
	start := time.Now()

	// 1) collect direct user roles
	roles, err := m.UR.ListRoles(ctx, userID)
	if err != nil {
		m.record(ctx, start, "Can", err)
		return false, err
	}

	// 2) collect groups this user belongs to
	groups, err := m.UG.GetGroupsByUserID(ctx, userID)
	if err != nil {
		m.record(ctx, start, "Can", err)
		return false, err
	}
	for _, ug := range groups {
		grpRoles, err := m.GR.ListRolesForGroup(ctx, ug.GroupName)
		if err != nil {
			m.record(ctx, start, "Can", err)
			return false, err
		}
		roles = append(roles, grpRoles...)
	}

	// 3) dedupe roles (optional)

	// 4) the old perm‐matching logic over all roles
	var allow bool
	for _, roleID := range roles {
		permIDs, err := m.RP.ListPermissions(ctx, roleID)
		if err != nil {
			m.record(ctx, start, "Can", err)
			return false, err
		}
		for _, pid := range permIDs {
			perm, err := m.Perms.GetPermissionByID(ctx, pid)
			if err != nil {
				m.record(ctx, start, "Can", err)
				return false, err
			}
			if perm == nil {
				continue
			}
			okRes, err := matchResource(perm.Resource, resource)
			if err != nil {
				m.record(ctx, start, "Can", err)
				return false, err
			}
			if !okRes {
				continue
			}
			okAct, err := path.Match(string(perm.Action), string(action))
			if err != nil {
				m.record(ctx, start, "Can", err)
				return false, err
			}
			if okAct {
				allow = true
				break
			}
		}
		if allow {
			break
		}
	}

	m.record(ctx, start, "Can", nil)
	return allow, nil
}

// matchResource remains unchanged...
func matchResource(pattern, resource string) (bool, error) {
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix, suffix := parts[0], parts[1]
		if !strings.HasPrefix(resource, prefix) {
			return false, nil
		}
		if suffix != "" && !strings.HasSuffix(resource, suffix) {
			return false, nil
		}
		if len(resource) < len(prefix)+len(suffix) {
			return false, nil
		}
		return true, nil
	}
	return path.Match(pattern, resource)
}
