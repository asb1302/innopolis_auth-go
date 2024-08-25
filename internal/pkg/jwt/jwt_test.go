package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Пример табличного unit-теста с использованием либы github.com/stretchr/testify
func TestIssueToken(t *testing.T) {
	privateKeyPEM := getTestPrivateKeyPEM()
	publicKeyPEM := getTestPublicKeyPEM()

	jwtManager, err := NewJWTManager("test_issuer", time.Hour, publicKeyPEM, privateKeyPEM)
	require.NoError(t, err)
	require.NotNil(t, jwtManager, "jwtManager should not be nil")

	tests := []struct {
		name          string
		userID        string
		expectedError error
	}{
		{
			name:          "Valid token generation",
			userID:        "user123",
			expectedError: nil,
		},
		{
			name:          "Empty user ID",
			userID:        "<nil>(<nil>)",
			expectedError: nil,
		},
		{
			name:          "Mismatched private key",
			userID:        "user123",
			expectedError: ErrValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Mismatched private key" {
				// пересоздаем jwtManager с неподходящим приватным ключом
				jwtManager, err = NewJWTManager("test_issuer", time.Hour, publicKeyPEM, getAnotherValidPrivateKeyPEM())
				require.NoError(t, err)
				require.NotNil(t, jwtManager, "jwtManager should not be nil")
			}

			token, err := jwtManager.IssueToken(tt.userID)
			if tt.expectedError != nil {
				parsedToken, err := jwtManager.VerifyToken(token)
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tt.expectedError))
				assert.Nil(t, parsedToken)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)

				parsedToken, err := jwtManager.VerifyToken(token)
				assert.NoError(t, err)
				assert.NotNil(t, parsedToken)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)
				assert.Equal(t, tt.userID, claims["sub"])
				assert.Equal(t, "test_issuer", claims["iss"])
			}
		})
	}
}

func getTestPrivateKeyPEM() []byte {
	return []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPtCam6ak5+vuCDNsiHLmDGEgwTx9pkazjN2LZMaiiUx
-----END PRIVATE KEY-----`)
}

func getTestPublicKeyPEM() []byte {
	return []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAW5On7WjQn8O55YZ4prIxx4coIEbTjZfV+xUyt4o6yX8=
-----END PUBLIC KEY-----
`)
}

// Недопустимый ключ, который вызовет ошибку при использовании
func getAnotherValidPrivateKeyPEM() []byte {
	return []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDhZZtuL9gUaHWa3GjLR/WyTf4Vla6U3km+0fD9elvqd
-----END PRIVATE KEY-----`)
}
