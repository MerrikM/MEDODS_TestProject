package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

type Claims struct {
	UserUUID         string `json:"user_id"`
	RefreshTokenUUID string `json:"refresh_token_id"`
	jwt.RegisteredClaims
}

type TokensPair struct {
	AccessToken  string
	RefreshToken string
}

var secretKey = []byte("SECRET_KEY=4baeef081535397ee96f810e4c205acc7364f1a9cf94b4508d9a")

const accessTokenTTL = time.Hour

func GenerateAccessRefreshTokens(userUUID string) (*TokensPair, string, string, error) {
	refreshToken, hashedToken, refreshUUID, err := GenerateRefreshToken()
	if err != nil {
		return nil, "", "", fmt.Errorf("ошибка генерации рефреш токена: %w", err)
	}

	claims := Claims{
		UserUUID:         userUUID,
		RefreshTokenUUID: refreshUUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "MEDODS_TestProject",
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := jwtToken.SignedString(secretKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("ошибка подписи токена: %w", err)
	}

	return &TokensPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, hashedToken, refreshUUID, nil
}

func GenerateRefreshToken() (string, string, string, error) {
	jwtTokenBytes := make([]byte, 32)
	_, err := rand.Read(jwtTokenBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("ошибка генерации: %w", err)
	}
	refreshUUID := uuid.New().String()
	refreshTokenStr := base64.StdEncoding.EncodeToString(jwtTokenBytes)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshTokenStr), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", fmt.Errorf("ошибка хэширования: %w", err)
	}

	// refreshTokenStr отдается клиенту
	// hashedToken сохраняется в БД
	return refreshTokenStr, string(hashedToken), refreshUUID, nil
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

func JWTMiddleware(secretKey []byte) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(handleAuthentication(secretKey, next))
	}
}

func handleAuthentication(secretKey []byte, next http.Handler) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		authorizationHeader := request.Header.Get("Authorization")
		if strings.HasPrefix(authorizationHeader, "Bearer ") == false {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}

		jwtTokenStr := strings.TrimPrefix(authorizationHeader, "Bearer ")

		claims, err := ValidateJWT(jwtTokenStr, secretKey)
		if err != nil {
			log.Printf("невалидный токен: %v", err)
			http.Error(writer, "невалидный токен", http.StatusUnauthorized)
			return
		}

		reuqest := request.WithContext(context.WithValue(request.Context(), "user", claims))
		next.ServeHTTP(writer, reuqest)
	}
}
