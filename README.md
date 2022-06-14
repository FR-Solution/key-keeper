# key-keeper

Пример config.yml
```yaml
vault:
    address: "address vault"
    token: "unexpired token"
    intermediate_ca_path: "path for saving intermediate ca"
    cert_path: "path for generate certificate"
    timeout: "timeout request: 1s, 3m, 5h"
certificate:
    common_name: "common_name"
    domain_name: "domain_name"
    cert_path: "path for save cert on host"
    key_path: "path for save key on host"
    valid_interval: "valid expire cert interval: 1s, 3m, 5h"
```
