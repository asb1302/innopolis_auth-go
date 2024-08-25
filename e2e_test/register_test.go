package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bogatyr285/auth-go/cmd/commands"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testServerPort = ":18082"
	dbDir          = "."
	dbFileName     = "test_db.sql"
)

type RegisterUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterUserResponse struct {
	Username string `json:"username"`
	ID       int    `json:"id"`
}

// Пример e2e теста
func TestRegisterUser(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jwt-keys")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	pubKeyPath, privKeyPath, err := createTempKeysInDir(tempDir)
	require.NoError(t, err)

	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		err = os.Mkdir(dbDir, 0755)
		require.NoError(t, err)
	}

	dbPath := filepath.Join(dbDir, dbFileName)

	_ = os.Remove(dbPath)

	configFile, err := createTempConfigFile(pubKeyPath, privKeyPath, dbPath)
	require.NoError(t, err)
	defer os.Remove(configFile.Name())

	// Запускаем сервер в тесте
	cmd := commands.NewServeCmd()
	cmd.SetArgs([]string{"--config", configFile.Name()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := cmd.ExecuteContext(ctx); err != nil {
			t.Fatalf("server execution failed: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	requestBody := RegisterUserRequest{
		Username: "testuser",
		Password: "testpassword",
	}
	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	resp, err := http.Post("http://localhost"+testServerPort+"/register", "application/json", bytes.NewBuffer(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var registerResponse RegisterUserResponse
	err = json.NewDecoder(resp.Body).Decode(&registerResponse)
	require.NoError(t, err)

	assert.Equal(t, "testuser", registerResponse.Username)
	//assert.NotZero(t, registerResponse.ID)
}

func createTempKeysInDir(dir string) (string, string, error) {
	pubKeyPath := filepath.Join(dir, "jwtRS256.key.pub")
	privKeyPath := filepath.Join(dir, "jwtRS256.key")

	err := os.WriteFile(pubKeyPath, []byte(pubKeyContent()), 0644)
	if err != nil {
		return "", "", err
	}

	err = os.WriteFile(privKeyPath, []byte(privKeyContent()), 0600)
	if err != nil {
		return "", "", err
	}

	return pubKeyPath, privKeyPath, nil
}

func createTempConfigFile(pubKeyPath, privKeyPath, dbPath string) (*os.File, error) {
	configContent := []byte(`
http_server:
  address: "` + testServerPort + `"
  timeout: "2s"
jwt:
  issuer: "auth-service"
  expires_in: "12h"
  public_key: "` + pubKeyPath + `"
  private_key: "` + privKeyPath + `"
storage:
  path: "` + dbPath + `"
`)

	configFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		return nil, err
	}

	if _, err := configFile.Write(configContent); err != nil {
		configFile.Close()
		os.Remove(configFile.Name())
		return nil, err
	}

	return configFile, nil
}

func pubKeyContent() string {
	return `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cOFtWpF7oVex1bLn/Xh
HvDy32voJg16tYExC/J5DslhXK6frMAATI2ej0Nv9tl+1jw9Rl87HIDfwMGEfsiF
+g+V6RRE6apdj5nZfKp4EWMVsSlS9y6YOzk7gTaFGXDVD4OJiLVFEoQHGqEAIQG2
6UEUtptVxtUvEfOPlXrlNgP6gvlA89IDG7pJcgqwcxOq4Hc/wwaeS2diPCjmphgk
hzx5lokod37HSbzi8L0yf9uPyB6NQdRMaAG+z97SBwFhH3xk1YaMVuqBEUxK43IC
oqSkSqPEyywE54ywElwnW2N64ndAUQXu+8UpOA/dsznEDuvLLIttdwCaHX/TCy+E
+wIDAQAB
-----END PUBLIC KEY-----
`
}

func privKeyContent() string {
	return `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvjAmKcw/zk6mX
1Ntgh/JNDDcCRV1Br3ID0aJSrJlXJHt/z0S/zvWxSdSok4PwSQUO+8atQn1bFTTT
uTVMRDigcGfKf7vTnPDEmMhAr4biheA8UFPRNZfmTDEATsjSEWjL+mlRt16/idhA
zhbM0Am37DBeF2t128nG7R66UC6EBXOQWHRARIv/AWooC47gMvgArckTZRketHLe
BGaoZu7X3ao27WkR9/fT1EsAdfS/nV8m282+uRGP0CqEM6+nnSBDRqtNmQfuv0Pk
tbgwiTHap11QrsS5og3rR4Oh2d4POzbguQ5C/1guU01ADpoUFKasMrvocl3r8phl
zNk3SBU3AgMBAAECggEAMG7ZBQdI6+GeJWNXYXMwkTxhAvHjUGeY89/HQrsXFXld
z33+kFMH63GcyCPm/4kN6bvibVQOZO5dZFrRjyi1XOKWaELErhY7QWqLuXkUJHRe
URWygmKgdawoytZxxq+B8+EzZJXMgNkFvp99n+V4APQbxiH9BofszEMIusu7gbXQ
HAd3IBv4YO9rCiadOvc6nGaeE+znLmlTIwunQ4eFDnxAPwdArEOLryBYaWu2jsdy
MHIvO8CeHP7XIkWAg5PthDntTle87URbHMh4lWThkkw5zUdKYr1n7FFRhtyy3a+K
JT5IPcrssi8gij6WYimyuVhPxXgmCXsaxqfD3PTtJQKBgQDiD/xkXB5NYxH6DEPn
tG9vH0l30MkWAkZ1yXGUA/mHTY0HlsgXD5EILf0TUuMzOIOjkSWSKEc2jrdRAN3X
fmzab0YJ5uud8FKYrN9MHfnWjkkbB/VyDWt5nc0EFbuppDLp2ZoEAFn7qiWqVsJZ
Dq6zvhP8ehz2wKv5KAAalqBh7QKBgQDGy3eloFvlnM8UdHijY70OZ1+80Z0fPvCh
xsjjZyWiv90b24oCkWVfVOmYHL20dbxL9OfeW3xBq5b7hO0bDL7oSlRpIgYpDrza
4vOPu0wDl+P1rnhMqYMPJHOyjKVOLGCD80Io1W9ZLGhTX3IPud7gAdlUMYS/Zo3M
X7GYn8B/MwKBgEdyd/mcJ7ObsS3PPJL5sxJy1/x3T2aWV4CYpz35t56swvr4C8tG
Dzd/mXHHC6m/ndNPZ4l3E3LJzmRamsKl4W90JbWxdxxWvTQlxvk+rBzEoZRagpeG
aEZqukYlPEeUbsb8EDJdjhL9JqRcgVY2Tr7eP2DXk1nlcTTxEH9Wxd/NAoGBAICc
G+D0WN+4ziP+ohmaqjIKYN7Iga04S/dtooO0NJ4RIJwoMSYuKHY/egyl83kvfk1p
uSSa7U2TFE/OlJMecNfZVrjZgUDIvxehIk/HrYrZlmpYoI2AUUDXpV5LLZrgjORw
2UmPo8T+PNRLeICCEJW9vHuCuc4WLACfnEcQezoPAoGBAJe5oyIrrp8EiRGzQRER
jr625MJ5tQXkF3EchZVOTLznc6uS3P2VWooi/QGufv/xGmWuOMffFO8SrorMmvC7
SptPooCDbN3bVFZLzeB7Z+qsPJwyxdWPoOFrIMwR7CZPXD7ARmbLMMQgZ7Gfal7G
EOyhr4rxZX+sGWrYea/WokGE
-----END PRIVATE KEY-----
`
}
