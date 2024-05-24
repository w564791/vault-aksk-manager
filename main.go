package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	vault "github.com/hashicorp/vault/api"
)

func main() {
	// Vault服务器地址
	var vaultAddress string
	// Vault中的KV路径
	var secretPath string
	var awsRegion string
	var duration string
	var err error
	auth_method := os.Getenv("AUTH_METHOD")
	duration = os.Getenv("DURATION")
	vaultAddress = os.Getenv("VAULT_ADDR")
	secretPath = os.Getenv("SECRET_PATH")
	awsRegion = os.Getenv("AWS_REGION")
	if duration == "" {
		duration = "3600"
	}
	if vaultAddress == "" {
		vaultAddress = "https://127.0.0.1:8100"
	}
	if secretPath == "" {
		panic(errors.New("kv path must not null"))
	}
	if awsRegion == "" {
		awsRegion = "ap-northeast-1"
	}

	var client *vault.Client
	var secret *vault.Secret
	if auth_method == "CERT" {
		client, secret, err = useCertLogin(vaultAddress)
		if err != nil {
			panic(err)
		}
		// 设置Token
		client.SetToken(secret.Auth.ClientToken)
	} else {
		client, err = useTokenLogin(vaultAddress)
		if err != nil {
			panic(err)
		}
	}

	// 读取KV存储中的数据
	kvSecret, err := client.Logical().Read(secretPath)
	if err != nil {
		log.Fatalf("failed to read secret from Vault: %v", err)
		return
	}

	if kvSecret == nil || kvSecret.Data == nil {
		log.Fatalf("no data found at path: %s", secretPath)
	}

	data, ok := kvSecret.Data["data"].(map[string]interface{})
	if !ok {
		log.Fatalf("data format is unexpected: %v", kvSecret.Data)
		return
	}
	ak, ok := data["ak"].(string)

	if !ok {
		panic(errors.New("ak is null"))
	}
	sk, ok := data["sk"].(string)
	if !ok {
		panic(errors.New("sk is null"))
	}
	SessionToken, err := getSessionToken(ak, sk, awsRegion, duration)
	if err != nil {
		panic(err)
	}

	newAKID := SessionToken.AccessKeyId
	newSKID := SessionToken.SecretAccessKey
	sessionToken := SessionToken.SessionToken

	// runExportAKID :=
	// runExportSKID :=
	// runSessionToken :=
	fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", *newAKID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", *newSKID)
	fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", *sessionToken)
	// if err = runShell(runExportAKID); err != nil {
	// 	panic(fmt.Errorf("run export ak err,%s", err.Error()))
	// }
	// if err = runShell(runExportSKID); err != nil {
	// 	panic(fmt.Errorf("run export sk err,%s", err.Error()))

	// }
	// if err = runShell(runSessionToken); err != nil {
	// 	panic(fmt.Errorf("run export session err,%s", err.Error()))

	// }
	// fmt.Println("export env success")
}

func getSessionToken(ak, sk, region, duration string) (sts.Credentials, error) {
	time_duration, err := strconv.ParseInt(duration, 10, 64)
	if err != nil {
		return sts.Credentials{}, err
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
		Credentials: credentials.NewStaticCredentials(
			ak,
			sk,
			"",
		),
	})
	if err != nil {
		return sts.Credentials{}, err
	}
	svc := sts.New(sess)
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(time_duration),
	}

	result, err := svc.GetSessionToken(input)
	if err != nil {
		return sts.Credentials{}, err
	}
	return *result.Credentials, nil
}

// func runShell(shell string) error {
// 	// var stdout bytes.Buffer
// 	// var stderr bytes.Buffer
// 	cmdExportAKID := exec.Command("zsh", "-c", shell)

// 	// cmdExportAKID.Stdout = &stdout
// 	// cmdExportAKID.Stderr = &stderr
// 	return cmdExportAKID.Run()

// }
func useCertLogin(vaultAddress string) (*vault.Client, *vault.Secret, error) {

	// 证书、私钥和CA证书文件路径
	clientCertFile := os.Getenv("VAULT_CLIENT_CERT")
	clientKeyFile := os.Getenv("VAULT_CLIENT_KEY")
	caCertFile := os.Getenv("VAULT_CACERT")

	// 加载客户端证书和私钥
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {

		return nil, nil, fmt.Errorf("failed to load client certificate and key: %v", err)
	}

	// 加载CA证书
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client certificate and key: %v", err)

	}

	// 创建证书池并添加CA证书
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 配置TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// 创建Vault客户端配置
	config := &vault.Config{
		Address:    vaultAddress,
		HttpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
	}

	// 创建Vault客户端
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client certificate and key: %v", err)

	}

	// 使用证书进行登录
	authPath := "auth/cert/login"
	authData := map[string]interface{}{}
	secret, err := client.Logical().Write(authPath, authData)
	return client, secret, err

}
func useTokenLogin(vaultAddress string) (*vault.Client, error) {
	config := vault.DefaultConfig()
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		panic(errors.New("token is null"))
	}
	config.Address = vaultAddress // 设置 Vault 服务器地址

	// 创建 Vault 客户端
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	// 使用 token 进行认证
	client.SetToken(token)

	// 设置 KV 路径
	return client, err
}
