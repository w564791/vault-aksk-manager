## 适用于aws aksk存放于vault管理

## 工作原理

使用valut存放aws aksk

agent获取aksk生成临时session token,默认有效期1小时

## 全局变量说明

AUTH_METHOD: 当前支持CERT以及token,默认为token验证

DURATION: 临时token有效期,默认1小时

VAULT_ADDR: vault地址: 默认https://127.0.0.1:8200

SECRET_PATH: 没有默认值,必传,请咨询vault管理员

AWS_REGION: aws region,默认为ap-northeast-1

### certificate验证必要变量

VAULT_CLIENT_CERT: 客户端证书

VAULT_CLIENT_KEY: 客户端私钥

VAULT_CACERT: ca证书

证书问题请联系vault管理员

### token验证(不推荐,仅测试验证使用)

VAULT_TOKEN: vault认证token

## 如何编译

本地使用: make build

linux使用: make build-linux

## 如何使用

将应用放到/usr/local/bin/vault-aksk-manager

执行如下shell

```

source <(/usr/local/bin/vault-aksk-manager)

```