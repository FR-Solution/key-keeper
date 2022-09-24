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
key-keeper -config-dir /path/to/config-dir -config-regexp .*.conf
```

> config-dir - путь до каталога с конфигами
>
> config-regexp - регуляроное выражения для имени файлов которые содержат конфиги для key-keeper


Example config.yml

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
          token: ${token}
        appRole:
          name: kubernetes-ca
          path: "clusters/cluster-1/approle"
          secretIDLocalPath: /var/lib/key-keeper/vault/kubernetes-ca/secret-id
          roleIDLocalPath: /var/lib/key-keeper/vault/kubernetes-ca/role-id
      certificate:
        role: kubelet-server
        CAPath: "clusters/cluster-1/pki/kubernetes"
        rootCAPath: "clusters/cluster-1/pki/root"
      kv:
        path: clusters/cluster-1/kv
      timeout: 15s

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
        commonName: "system:node:master-0.cluster-1.dobry-kot.ru"
      usage:
        - server auth
      privateKey:
        algorithm: "RSA"
        encoding: "PKCS1"
        size: 4096
      ipAddresses:
        interfaces:
          - lo
          - eth*
      ttl: 200h
      hostnames:
        - localhost
        - "master-0.cluster-1.dobry-kot.ru"
    renewBefore: 100h
    hostPath: "/etc/kubernetes/pki/certs/kubelet"


secrets:
  - name: kube-apiserver-sa
    issuerRef:
      name: kube-apiserver-sa
    key: public  
    hostPath: /etc/kubernetes/pki/certs/kube-apiserver/kube-apiserver-sa.pub

```
