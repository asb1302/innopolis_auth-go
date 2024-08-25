package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// for now there's no reason for err segregation & uniq processing
	// but its good idea to have list of error which module can return
	ErrKeyParsing      = fmt.Errorf("parsing error")
	ErrTokenGeneration = fmt.Errorf("token generation error")
	ErrSigning         = fmt.Errorf("signing error")
	ErrValidation      = fmt.Errorf("token validation errror")
)

type JWTManager struct {
	issuer     string
	expiresIn  time.Duration
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewJWTManager(issuer string, expiresIn time.Duration, publicKeyPEM, privateKeyPEM []byte) (*JWTManager, error) {
	pubBlock, _ := pem.Decode(publicKeyPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		return nil, ErrKeyParsing
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, ErrKeyParsing
	}

	edPubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrKeyParsing
	}

	privBlock, _ := pem.Decode(privateKeyPEM)
	if privBlock == nil || privBlock.Type != "PRIVATE KEY" {
		return nil, ErrKeyParsing
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, ErrKeyParsing
	}

	edPrivKey, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrKeyParsing
	}

	return &JWTManager{
		issuer:     issuer,
		expiresIn:  expiresIn,
		publicKey:  edPubKey,
		privateKey: edPrivKey,
	}, nil
}

func (j *JWTManager) IssueToken(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    j.issuer,
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.expiresIn)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signed, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}
	return signed, nil
}

func (j *JWTManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrValidation
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}

	return token, nil
}
