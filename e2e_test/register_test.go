package e2e_test

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

const (
	baseURL = "http://localhost:18005"
)

type RegisterUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterUserResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// Пример e2e теста с использованием приложения в docker-контейнере
func TestRegisterUser(t *testing.T) {
	requestBody := RegisterUserRequest{
		Username: "testuser",
		Password: "testpassword",
	}
	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/register", "application/json", bytes.NewBuffer(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var registerResponse RegisterUserResponse
	err = json.NewDecoder(resp.Body).Decode(&registerResponse)
	require.NoError(t, err)

	assert.Equal(t, "testuser", registerResponse.Username)
	//assert.NotZero(t, registerResponse.ID)
}
