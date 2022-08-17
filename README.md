# key-keeper

## Build & Push image

Поменять версию релиза в .release и выполнить:

```bash
make build-and-push DOCKER_USER=geoirb
```

# Build bin

```bash
go build -o key-keeper cmd/key-keeper/main.go
```

# Run bim

```bash
key-keeper -config /path/to/config
```

Example config.yml

```yaml
---
vault:
  address: "http://${VAULT_IP}" # Адрес волта
  bootstrap_token: ${VAULT_TOKEN} # Токен для получения secret_id и role_id
  # С secret_id и role_id происходит базовая авторизация и получения временного токена.
  local_path_to_role_id: "role_id" # Путь где будет сохранен файл с role_id
  local_path_to_secret_id: "secret_id" # Путь где будет сохранен файл с secret_id
  approle_path: clusters/cluster-1/approle # Путь до аппроли
  approle_name: test-role # Название аппроли (для теста выдели аппроль и навесь рут)
  request_timeout: "10m" # Таймаут ответа Vault
certificates:
  # Для совместного использования приватного ключа CA,Intermidiat
  # - public and private помещается в KV с наименованием ${COMMON_NAME}
  vault_kv: "clusters/cluster-1/kv"
  reissue_interval: "1d" # интервал перевыпуск - за сутки до истечения перевыпустить. (Хардкод - проверяет раз в час)
  # Блок Root_CA отвечает за выпуск корневых сертификатов - на выход не получаем ни сертификат ни ключ от него
  # что бы все сертификаты выпускались только с Intermediate.
  root_ca:
    - common_name: "test" # CN
      root_path_ca: "clusters/cluster-1/pki/root" # Путь к сейфу

  # Блок Intermediate_ca отвечает за выпуск промежуточных сертификатов
  # Все сертификаты выпускаются в этих сейфах
  intermediate_ca:
    - common_name: "kubernetes" # CN
      root_path_ca: "clusters/cluster-1/pki/root" # Путь к сейфу корневого CA
      cert_path: "clusters/cluster-1/pki/kubernetes" # Путь к сейфу Inermediate CA
      host_path: "/etc/kubernetes/pki/ca/root-ca" # Локальный путь, где будет размещен public / private keys
      exported_key: false # Этот флаг заказывает Inermediate типа internal/external (в отпут придет private-key или нет)
      generate: false # Этот флаг отвечает за сценарий создания нового CA или чтение существующего.

  csr:
    - common_name: "system:kube-apiserver-front-proxy-client" # CN
      role: "base-role" # system_masters_client                   # Роль в которой прописаны критерии сертификата (usages,access_ip,access_san,etc)
      host_path: "/etc/kubernetes/pki/certs/kube-apiserver/cert" # Локальный путь, где будет размещен public / private keys
      cert_path: "clusters/cluster-1/pki/kube-apiserver" # Путь к сейфу Inermediate CA где будет заказан сертификат
      trigger: # Триггер выполняемый при обновлении данного csr
        - "cmd commands"
keys:
  vault_kv: ""

  rsa:
    - name: ""
    - host_path: ""
```
