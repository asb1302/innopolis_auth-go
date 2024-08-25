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
MCowBQYDK2VwAyEAW5On7WjQn8O55YZ4prIxx4coIEbTjZfV+xUyt4o6yX8=
-----END PUBLIC KEY-----
`
}

func privKeyContent() string {
	return `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPtCam6ak5+vuCDNsiHLmDGEgwTx9pkazjN2LZMaiiUx
-----END PRIVATE KEY-----`
}
