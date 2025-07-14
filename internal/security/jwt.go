package security

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Roles    []string
	jwt.RegisteredClaims
}

const secretKey = "SECRET_KEY=4baeef081535397ee96f810e4c205acc7364f1a9cf94b4508d9a"

func GenerateWJT(userID string, username string, roles []string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "MEDODS_TestProject",
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return jwtToken.SignedString(secretKey)
}

func GenerateRefreshToken() (string, error) {
	return uuid.NewString(), nil
}

func ValidateJWT(jwtTokenStr string, secretKey []byte) (*Claims, error) {
	var claims = &Claims{}

	jwtToken, err := jwt.ParseWithClaims(jwtTokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Header["alg"] != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("неверный способ подписи токена: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil || jwtToken.Valid == false {
		return nil, fmt.Errorf("невалидный токен: %w", err)
	}

	return claims, nil
}

func JWTAuthorizationMiddleware(secretKey []byte) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(handleAuthorization(secretKey, next))
	}
}

func handleAuthorization(secretKey []byte, next http.Handler) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		authorizationHeader := request.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}

		jwtTokenStr := strings.TrimPrefix(authorizationHeader, "Bearer ")

		claims, err := ValidateJWT(jwtTokenStr, secretKey)
		if err != nil {
			http.Error(writer, "невалидный токен", http.StatusUnauthorized)
			return
		}

		reuqest := request.WithContext(context.WithValue(request.Context(), "user", claims))
		next.ServeHTTP(writer, reuqest)
	}
}
