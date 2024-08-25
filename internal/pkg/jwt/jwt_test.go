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
			userID:        "",
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
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRw4W1akXuhV7H
Vsuf9eEe8PLfa+gmDXq1gTEL8nkOyWFcrp+swABMjZ6PQ2/22X7WPD1GXzscgN/A
wYR+yIX6D5XpFETpql2Pmdl8qngRYxWxKVL3Lpg7OTuBNoUZcNUPg4mItUUShAca
oQAhAbbpQRS2m1XG1S8R84+VeuU2A/qC+UDz0gMbuklyCrBzE6rgdz/DBp5LZ2I8
KOamGCSHPHmWiSh3fsdJvOLwvTJ/24/IHo1B1ExoAb7P3tIHAWEffGTVhoxW6oER
TErjcgKipKRKo8TLLATnjLASXCdbY3rid0BRBe77xSk4D92zOcQO68ssi213AJod
f9MLL4T7AgMBAAECggEAD1ulFDBGEyhOqoJPVv81+Vb44U98PXT/2/7WgXfCUfPV
SLzm/KCeJPy6yZB4HSG1ff1bxdA+erVw1yMUDq2jKY4vPVPPloVzuN+HI0Uz6fSl
kkVinq3EVZRjfUVpn1WPM/CUhvQxV3a1MnJBQ9QP+VSw2IyCTj7Y5b6TGlsCId8s
xBlYA3tgO1dKkFQacc1UjJzWzxGIRhyY1x3Kav1UHHuqE7KQCzrJsQqEIoH9rTr2
c1m4InbZf3vDxwu4kscqde9gPBZDZDaL3VRwV6rKbCcnSvnDttOuwY4uljO7U+/C
m0brcDPljNlGICN1bRnOoxHi8KFhBcZwHKcN322o8QKBgQDpkgA4WTKk/uE7DaEh
Ek4qERdy6dali+YGBuVMBJBLCipPhtDnuDIah19w6+MCZg/ay9F5fi2RG0fNOH6a
px5HDyTWMQzf+bCeN91oAIR7KmCAd2RKBPv5htm3Bvw1PDamA9P25i9QgHHNiH22
frKB2Ll/Mfr89DvSXBlUQhThkwKBgQDl6EVEdM+T0UqhLvi3GDmYiXHdLdIgEdD7
Q+b06f76mDQVgGsH8EkWMQ8dj8qnFNXg7kc8aJkqHI2qYG6x6jmAVX6nsXLjzpEK
iC4Lseh91XoJf4AR1cfjZ4ya8mOd1/IZBAuEFH9HCKoAwJOnBjBPISFQBhI6PmZ+
7OQcYQWP+QKBgGcKce5p612+074plRvx52nHgIDBiGAgB6pBAIc4vC9enKvY3fBb
4j6x2fkHF27Hd9cec5sVfyS01EhE1BWGBGV02NtlaDim/rPOEW8AS3HKkCgcg7Hj
4QWD6ChGfJ0/oxw6NBiIE/d/srTpsgwAeN+vrKXgdsmBNaLn3oS9YljhAoGAVy6h
NbhmDtPKzRyWzDevf5x/RTRe/jJDYUT6i91AB584AP9VlwkTbgrkhH1Gh91qzYUO
FmZDzqhNQFKZJ3Z+n5/MC6NKwgBPGANUErNASpdtU7S5yAmdZyqZMxi/ldeRwtK5
2zg6m6E5dleQpkG+iAM0MrhaqSOIkpEaX3ibN2ECgYEAl2q9DV0NmpL5ZPCH7YZu
zMkNVBIB8cNQVOPxX0vvQzB6wVD5WAiJ/w9PLv2vsKmtBIpTwKcdS0DlysJHSQ3M
93WAm8VjzXP/x+wJ7+54HXXveWr0KrfYpkmbvtDS8yQpe58rtomhUuL8GRUxXnyJ
4+OuiVdP4ORGD0/g+jVuQKU=
-----END PRIVATE KEY-----
`)
}

func getTestPublicKeyPEM() []byte {
	return []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cOFtWpF7oVex1bLn/Xh
HvDy32voJg16tYExC/J5DslhXK6frMAATI2ej0Nv9tl+1jw9Rl87HIDfwMGEfsiF
+g+V6RRE6apdj5nZfKp4EWMVsSlS9y6YOzk7gTaFGXDVD4OJiLVFEoQHGqEAIQG2
6UEUtptVxtUvEfOPlXrlNgP6gvlA89IDG7pJcgqwcxOq4Hc/wwaeS2diPCjmphgk
hzx5lokod37HSbzi8L0yf9uPyB6NQdRMaAG+z97SBwFhH3xk1YaMVuqBEUxK43IC
oqSkSqPEyywE54ywElwnW2N64ndAUQXu+8UpOA/dsznEDuvLLIttdwCaHX/TCy+E
+wIDAQAB
-----END PUBLIC KEY-----
`)
}

// Недопустимый ключ, который вызовет ошибку при использовании
func getAnotherValidPrivateKeyPEM() []byte {
	return []byte(`-----BEGIN PRIVATE KEY-----
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
`)
}
