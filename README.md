# key-keeper

инструмент для linux хостов, позволяющий заказывать в Vault хранилище сертификаты и секреты и следить за их актуальностью.

## Build & Push image

Поменять версию релиза в .release и выполнить:

```bash
make build-and-push DOCKER_USER=geoirb
```

## Build bin

```bash
go build -o key-keeper cmd/key-keeper/main.go
```

## Run bin

```bash
key-keeper -config-dir /path/to/config-dir -config-regexp .*.conf
```

> config-dir - путь до каталога с конфигами
>
> config-regexp - регуляроное выражения для имени файлов которые содержат конфиги для key-keeper

## Описание структуры конфигов:

#### ISSUERS:

| ключ                                    | тип    | описание                                                                |
| --------------------------------------- | ------ | ----------------------------------------------------------------------- |
| **`issuers `**                          | list   | список инструкций подключений                                           |
| `.name`                                 | string | имя инструкции                                                          |
| `.vault.server`                         | string | адрес Vault server                                                      |
| `.vault.auth.caBundle`                  | object | ca bundle для tls                                                       |
| `.vault.auth.tlsInsecure`               | bool   | отключение проверки tls                                                 |
| `.vault.auth.bootstrap`                 | object | описание метода авторизации для получения secret_id_role_id             |
| `.vault.auth.bootstrap.tokenPath`       | string | временный токен Vault                                                   |
| `.vault.auth.bootstrap.file`            | string | путь к временномсу токену Vault                                         |
| `.vault.auth.appRole`                   | object | описание авторизации по approle                                         |
| `.vault.auth.appRole.name`              | string | имя approle                                                             |
| `.vault.auth.appRole.path`              | string | базовый путь approle в Vault                                            |
| `.vault.auth.appRole.roleIDLocalPath`   | string | локальный путь, где будет искать role_id для авторизации                |
| `.vault.auth.appRole.secretIDLocalPath` | string | локальный путь, где будет искать secret_id для авторизации              |
| `.vault.resource`                       | object | инструция доступа к vault роли для выпуска сертификата                  |
| `.vault.resource.role`                  | string | имя роли через которую будет выпускаться сертификат                     |
| `.vault.resource.CAPath `               | string | базовый путь PKI хранилища, где прописана роль                          |
| `.vault.resource.rootCAPath`            | string | базовый путь PKI root хранилища от кого будет выписываться intermediate |
| `.vault.resource.kv`                    | object | описание доступа в Vault к Key Value стореджу                           |
| `.vault.resource.kv.path`               | string | путь в Vault до Key Value стореджа                                      |
| `.vault.timeout `                       | string | максимальное время ответа сервера Vault                                 |

```yaml
---
issuers:
  - name: kubernetes-ca
    vault:
      server: http://example.com:9200
      auth:
        caBundle:
        tlsInsecure: true
        bootstrap:
          token: ${token} # <- или
          path: /tmp/bootstrap-token # <- или
        appRole:
          name: kubernetes-ca
          path: "clusters/cluster-1/approle"
          secretIDLocalPath: /var/lib/key-keeper/vault/kubernetes-ca/secret-id
          roleIDLocalPath: /var/lib/key-keeper/vault/kubernetes-ca/role-id
      resource:
        role: kubelet-server
        CAPath: "clusters/cluster-1/pki/kubernetes"
        rootCAPath: "clusters/cluster-1/pki/root"
        kv:
          path: "clusters/cluster-1/kv"
```

#### CERTIFICATES:

| ключ                               | тип     | описание                                                                                  |
| ---------------------------------- | ------- | ----------------------------------------------------------------------------------------- |
| **`certificates `**                | list    | список инструкций заказа сертификатов из Vault                                            |
| `.name`                            | string  | имя инструкции                                                                            |
| `.issuerRef`                       | object  | ссылка на инструкцию issuer через которую произведется авторизация                        |
| `.issuerRef.name`                  | string  | имя инструкции issuer                                                                     |
| `.isCa`                            | bool    | указатель, что заказывается сертификат типа CA                                            |
| `.ca`                              | object  | описание расширения для заказа CA                                                         |
| `.ca.exportedKey`                  | bool    | инструкция - запрашивать приватный ключ или нет (требуется pki типа external)             |
| `.ca.generate`                     | bool    | создаст intermediate или запросит существующий (требуются права на создание intermediate) |
| `.spec`                            | object  | поля для генерации сертификата                                                            |
| `.spec.subject`                    | object  | Описывает принадлежность сертификата к...                                                 |
| `.spec.subject.commonName`         | string  | \*                                                                                        |
| `.spec.subject.country`            | list    | \*                                                                                        |
| `.spec.subject.localite`           | list    | \*                                                                                        |
| `.spec.subject.organization`       | list    | \*                                                                                        |
| `.spec.subject.organizationalUnit` | list    | \*                                                                                        |
| `.spec.subject.province`           | list    | \*                                                                                        |
| `.spec.subject.postalCode`         | list    | \*                                                                                        |
| `.spec.subject.streetAddress`      | list    | \*                                                                                        |
| `.spec.subject.serialNumber`       | string  | \*                                                                                        |
| `.spec.privateKey`                 | object  | Описание алгоритма для приватного ключа                                                   |
| `.spec.privateKey.algorithm`       | string  | Алгоритм                                                                                  |
| `.spec.privateKey.encoding`        | string  | Метод формирования                                                                        |
| `.spec.privateKey.size`            | integer | 2048 / 4096                                                                               |
| `.spec.hostnames`                  | list    | список имен для блока alternative names                                                   |
| `.spec.ipAddresses`                | object  | описывает какие ip адреса попадут в ipSans                                                |
| `.spec.ipAddresses.static`         | list    | список статичных ip адресов который попадет в ipSans                                      |
| `.spec.ipAddresses.interfaces`     | list    | список ip адресов, взятый с интерфейсов хоста, попадет в ipSans                           |
| `.spec.ipAddresses.dnsLookup`      | list    | список ip адресов, взятый из функции dnslookup статичной A записи, попадет в ipSans       |
| `.spec.ttl`                        | string  | срок на который заказывается сертификат                                                   |
| `.hostPath`                        | string  | путь в локальной файловой системе, где будет сохранен сертификат                          |
| `.withUpdate`                      | bool    | данный параметр создаст сертификат без последующего перевыпуска                           |
| `.updateBefore`                    | string  | время до истечения сертификата - при достижении сертификат перевыпустится                 |
| `.trigger`                         | list    | список баш команд, которые выполнятся после обновления сертификата                        |

```yaml
certificates:
  - name: kubernetes-ca
    issuerRef:
      name: kubernetes-ca
    isCa: true
    ca:
      exportedKey: false
      generate: false
    hostPath: "/etc/kubernetes/pki/ca"

  - name: kubelet-server
    issuerRef:
      name: kubelet-server
    spec:
      subject:
        commonName: "system:node:master-0.cluster-1.example.com"
      usage:
        - server auth
      privateKey:
        algorithm: "RSA"
        encoding: "PKCS1"
        size: 4096
      ipAddresses:
        static:
          - 1.1.1.1
        ###
        # * -> Позволяет указывать регексп интерфейсов (на выходе получаем список)
        interfaces:
          - lo
          - eth*
        ###
        # * -> В цикле будет пытаться отрезолвить имя, без выходного значения, сертификат не будет заказан.
        dnsLookup:
          - api.example.com
      ttl: 200h
      ###
      # * -> Указав $HOSTNAME - hostname хоста добавится в поле AltNames сертификата.
      hostnames:
        - $HOSTNAME
        - localhost
        - "master-0.cluster-1.example.com"
    renewBefore: 100h
    hostPath: "/etc/kubernetes/pki/certs/kubelet"
```

#### SECRETS:

| ключ              | тип    | описание                                                           |
| ----------------- | ------ | ------------------------------------------------------------------ |
| **`secrets `**    | list   | список инструкций заказа секрета из Vault                          |
| `.name`           | string | имя инструкции и одновременно имя секрета в Vault                  |
| `.issuerRef`      | object | ссылка на инструкцию issuer через которую произведется авторизация |
| `.issuerRef.name` | string | имя инструкции issuer                                              |
| `.key`            | string | ключ в объекта секрета                                             |
| `.hostPath`       | string | путь в локальной файловой системе, где будет сохранен секрет       |

```yaml
secrets:
  - name: kube-apiserver-sa
    issuerRef:
      name: kube-apiserver-sa
    key: public
    hostPath: /etc/kubernetes/pki/certs/kube-apiserver/kube-apiserver-sa.pub
```
