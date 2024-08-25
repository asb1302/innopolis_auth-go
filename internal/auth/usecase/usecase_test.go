package usecase

import (
	"context"
	"testing"

	"github.com/bogatyr285/auth-go/internal/auth/entity"
	"github.com/bogatyr285/auth-go/internal/buildinfo"
	"github.com/bogatyr285/auth-go/internal/gateway/http/gen"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Тестируем успешный логин с использование моков
func TestPostLoginSuccessful(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCrypto := new(MockCryptoPassword)
	mockJWT := new(MockJWTManager)

	authUseCase := NewUseCase(mockUserRepo, mockCrypto, mockJWT, buildinfo.BuildInfo{})
	setupMocksForSuccessfulLogin(mockUserRepo, mockCrypto, mockJWT)

	request := gen.PostLoginRequestObject{
		Body: &gen.PostLoginJSONRequestBody{
			Username: "testuser",
			Password: "password",
		},
	}

	expectedResult := gen.PostLogin200JSONResponse{
		AccessToken: "mockToken",
	}

	response, err := authUseCase.PostLogin(context.Background(), request)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, response)

	mockUserRepo.AssertExpectations(t)
	mockCrypto.AssertExpectations(t)
	mockJWT.AssertExpectations(t)
}

// Мок для UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) RegisterUser(ctx context.Context, u entity.UserAccount) error {
	args := m.Called(ctx, u)

	return args.Error(0)
}

func (m *MockUserRepository) FindUserByEmail(ctx context.Context, username string) (entity.UserAccount, error) {
	args := m.Called(ctx, username)

	return args.Get(0).(entity.UserAccount), args.Error(1)
}

// Мок для CryptoPassword
type MockCryptoPassword struct {
	mock.Mock
}

func (m *MockCryptoPassword) HashPassword(password string) ([]byte, error) {
	args := m.Called(password)

	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoPassword) ComparePasswords(fromUser, fromDB string) bool {
	args := m.Called(fromUser, fromDB)

	return args.Bool(0)
}

// Мок для JWTManager
type MockJWTManager struct {
	mock.Mock
}

func (m *MockJWTManager) IssueToken(userID string) (string, error) {
	args := m.Called(userID)

	return args.String(0), args.Error(1)
}

func (m *MockJWTManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	args := m.Called(tokenString)

	return args.Get(0).(*jwt.Token), args.Error(1)
}

// Приватная функция для настройки моков
func setupMocksForSuccessfulLogin(
	mockUserRepo *MockUserRepository,
	mockCrypto *MockCryptoPassword,
	mockJWT *MockJWTManager,
) {
	mockUserRepo.On("FindUserByEmail", mock.Anything, "testuser").Return(entity.UserAccount{
		Username: "testuser",
		Password: "hashedpassword",
	}, nil)
	mockCrypto.On("ComparePasswords", "hashedpassword", "password").Return(true)
	mockJWT.On("IssueToken", "testuser").Return("mockToken", nil)
}
