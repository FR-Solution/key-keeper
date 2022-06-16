# key-keeper

Example config.yml

```yaml
vault:
  address: "address vault"
  token: "unexpired token"
  path_to_role_id: "path to local role id"
  path_to_secret_id: "path to local secret id"
  timeout: "timeout request: 1s, 3m, 5h"
certificates:
  root_path: "root ca path"
  cert_path: "path for generate certificate"
  vault_kv: "path for kv"
  valid_interval: "valid expire cert interval: 1s, 3m, 5h"
  ca:
    common_name: "common_name"
    host_path: "path for store of ca in host"
  csr:
    - common_name: "common_name"
      role: "role for generate cert"
      host_path: "path for store of ca in host"
```

Build:

    go build -o key-keeper cmd/key-keeper/main.go

Run:

    key-keeper -config /path/to/config
