package handler

import (
	"MEDODS_TestProject/internal/security"
	"MEDODS_TestProject/internal/service"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

type AuthenticationHandler struct {
	*service.AuthenticationService
}

type CurrentUserResponse struct {
	UserGUID string `json:"userGUID"`
}

type TokensPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type LogoutResponse struct {
	Message string
}

func NewAuthenticationHandler(authenticationService *service.AuthenticationService) *AuthenticationHandler {
	return &AuthenticationHandler{authenticationService}
}

func (handler *AuthenticationHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()

	guid := request.URL.Query().Get("guid")

	tokensPair, refreshToken, err := handler.JWTService.GenerateAccessRefreshTokens(guid)
	if err != nil {
		log.Printf("ошибка генерации токенов: %v", err)
		http.Error(writer, "ошибка генерации токенов", http.StatusInternalServerError)
		return
	}

	refreshToken.UserAgent = request.UserAgent()
	refreshToken.IpAddress = request.RemoteAddr

	err = handler.JWTRepository.SaveRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("ошибка сохранения рефреш токена: %v", err)
		http.Error(writer, "ошибка сохранения токена", http.StatusInternalServerError)
		return
	}

	response := &TokensPair{
		AccessToken:  tokensPair.AccessToken,
		RefreshToken: tokensPair.RefreshToken,
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}

func (handler *AuthenticationHandler) GetCurrentUsersUUID(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()

	claims, ok := ctx.Value("user").(*security.Claims)
	if ok == false || claims == nil {
		http.Error(writer, "не авторизован", http.StatusUnauthorized)
		return
	}

	response := &CurrentUserResponse{UserGUID: claims.UserUUID}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}

func (handler *AuthenticationHandler) RefreshToken(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()

	authHeader := request.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(writer, "пустой или неверный заголовок Authorization", http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	ipAddress := request.RemoteAddr
	userAgent := request.UserAgent()

	var refreshTokenRequest RefreshTokenRequest
	if err := json.NewDecoder(request.Body).Decode(&refreshTokenRequest); err != nil {
		log.Printf("неверный json: %v", err)
		http.Error(writer, "неверный json", http.StatusBadRequest)
		return
	}

	tokensPair, err := handler.AuthenticationService.RefreshToken(
		ctx,
		userAgent,
		ipAddress,
		accessToken,
		refreshTokenRequest.RefreshToken,
	)
	if err != nil {
		log.Printf("не удалось обновить токены: %v", err)
		http.Error(writer, "не удалось обновить токены", http.StatusUnauthorized)
		return
	}

	response := &TokensPair{
		AccessToken:  tokensPair.AccessToken,
		RefreshToken: tokensPair.RefreshToken,
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}

func (handler *AuthenticationHandler) Logout(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()

	claims, ok := ctx.Value("user").(*security.Claims)
	if ok == false || claims == nil {
		http.Error(writer, "не авторизован", http.StatusUnauthorized)
		return
	}

	err := handler.AuthenticationService.Logout(ctx, claims.RefreshTokenUUID)
	if err != nil {
		http.Error(writer, "ошибка запроса", http.StatusBadRequest)
		return
	}
	response := &LogoutResponse{Message: "выполнен выход из аккаунта"}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}
