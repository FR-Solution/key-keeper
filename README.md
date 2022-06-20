# key-keeper

Example config.yml

```yaml
vault:
  address: "address vault"
  bootstrap_token: "unexpired token"
  approle_path: "role-path"
  approle_name: "role-name"
  local_path_to_role_id: "path to local role id"
  local_path_to_secret_id: "path to local secret id"
  request_timeout: "timeout request: 1s, 3m, 5h"
certificates:
  vault_kv: "path for kv"
  reissue_interval: "interval for initialization reissue certificate: 1s, 3m, 5h"
  ca:
    - common_name: "common_name"
      root_path_ca: "root ca path"
  intermediate_ca:
    - common_name: "common_name"
      root_path_ca: "root ca path"
      cert_path: "path for generate certificate"
      # флаг указывающий на генерацию с экспортируемым ключом
      exporting_key: true | false
      # флаг показывающий что генерация сертификата не нужна
      read_only: true | false
      host_path: "path for store of ca in host"
  csr:
    - common_name: "common_name"
      hosts:
        - "host1"
        - "host2"
      ips:
        - "127.127.0.7"
        - "127.127.0.9"
      root_path_ca: "root ca path"
      cert_path: "path for generate certificate"
      role: "role for generate cert"
      host_path: "path for store of ca in host"
```

Build:

    go build -o key-keeper cmd/key-keeper/main.go

Run:

    key-keeper -config /path/to/config
