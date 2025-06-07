# RBAC Go Package

A flexible, storage-agnostic Role-Based Access Control (RBAC) library for Go. Defines core domain types, repository interfaces, and a high-level `Manager` to handle permission and role checks. Includes a MongoDB implementation, in-memory testing stub, wildcard and fuzzy matching, benchmarks, and unit tests.

## Features

* **Storage-agnostic**: Define `PermissionRepo`, `RoleRepo`, `UserRepo`, `RolePermissionRepo`, and `UserRoleRepo` interfaces to plug in any backend (MongoDB, SQL, in-memory, etc.).
* **High-level Manager**: `Manager` struct orchestrates CRUD and business logic: creating/deleting users, roles, permissions; assigning roles and permissions; checking access via `Can`.
* **Wildcard support**:

    * **Action wildcard** (`*`) grants all actions on a resource (e.g. `survey,*`).
    * **Resource single-segment wildcard** (`*`) matches exactly one segment between dots (e.g. `survey.*.test` matches `survey.foo.test`).
    * **Resource multi-segment wildcard** (`**`) matches zero or more segments (e.g. `survey.**.test` matches `survey.test`, `survey.foo.test`, or `survey.foo.bar.test`).
    * **Global wildcard** (`*`) on resource matches any resource name (e.g. `*`).

## Installation

```bash
go get github.com/Seann-Moser/rbac
```

## Quick Start

```go
package main

import (
  "context"
  "fmt"
  "log/slog"

  "github.com/Seann-Moser/rbac"
  "go.mongodb.org/mongo-driver/mongo"
  "go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
  // MongoDB setup
  client, _ := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
  db := client.Database("mydb")

  // Create store and manager
  mgr,err := rbac.NewMongoStoreManager(context.Background(),db)
  if err != nil {
    slog.Error("failed setting up manager","err",err)
    return
  }
  ctx := context.Background()

  // Create a permission and a role
  perm := &rbac.Permission{Resource: "survey.*", Action: rbac.ActionAll}
  err = mgr.CreatePermission(ctx, perm)
  if err != nil {
    slog.Error("failed creating permission","err",err)
	return
  }
  role := &rbac.Role{Name: "admin"}
  err = mgr.CreateRole(ctx, role)
  if err != nil {
    slog.Error("failed creating permission","err",err)
    return
  }
  err = mgr.AssignPermissionToRole(ctx, role.ID, perm.ID)
  if err != nil {
    slog.Error("failed assigning permission to role","err",err)
    return
  }

  // Assign role to user
  user := &rbac.User{Username: "alice", Email: "alice@example.com"}
  err = mgr.CreateUser(ctx, user)
  if err != nil {
    slog.Error("failed creating user","err",err)
    return
  }
  
  err = mgr.AssignRoleToUser(ctx, user.ID, role.ID)
  if err != nil {
    slog.Error("failed assigning user to role","err",err)
    return
  }

  // Check access
  ok, _ := mgr.Can(ctx, user.ID, "survey.123.test", rbac.ActionRead)
  fmt.Println("Access granted?", ok)
}
```

## Testing

* **Unit tests**:

  ```bash
    go test ./...   # includes CRUD, wildcard, fuzzy tests
  ```




* **Benchmarks**:

    ```bash
    go test -bench=. ./...
    ```
  
    ```bash
    goos: linux
    goarch: amd64
    pkg: github.com/Seann-Moser/rbac
    cpu: AMD Ryzen 7 3700X 8-Core Processor             
    BenchmarkCan_NoRoles-16                         228800782                5.279 ns/op
    BenchmarkCan_SingleRoleSinglePerm-16             3909104               306.9 ns/op
    BenchmarkCan_ManyRolesManyPerms-16                199101              6338 ns/op
    BenchmarkCan_ResourceWildcard-16                 2649585               446.6 ns/op
    PASS
    ok      github.com/Seann-Moser/rbac     6.241s
    
    ```
## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Write code and tests
4. Update this README
5. Submit a pull request

## License

MIT © Seann Moser

