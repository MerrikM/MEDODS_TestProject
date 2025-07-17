package handler

import (
	"MEDODS_TestProject/internal/security"
	"MEDODS_TestProject/internal/service"
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

const accessTokenTTL = time.Hour

func NewAuthenticationHandler(authenticationService *service.AuthenticationService) *AuthenticationHandler {
	return &AuthenticationHandler{authenticationService}
}

func (handler *AuthenticationHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	guid := request.URL.Query().Get("guid")

	tokensPair, refreshToken, err := security.GenerateAccessRefreshTokens(guid)
	if err != nil {
		log.Printf("ошибка генерации токенов: %v", err)
		http.Error(writer, "ошибка генерации токенов", http.StatusInternalServerError)
		return
	}

	err = handler.JWTRepository.SaveRefreshToken(request.Context(), refreshToken)
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
	claims, ok := request.Context().Value("user").(*security.Claims)
	if !ok || claims == nil {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

	response := &CurrentUserResponse{UserGUID: claims.UserUUID}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}

func (handler *AuthenticationHandler) RefreshToken(writer http.ResponseWriter, request *http.Request) {
	accessToken := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")

	var refreshTokenRequest RefreshTokenRequest
	if err := json.NewDecoder(request.Body).Decode(&refreshTokenRequest); err != nil {
		log.Printf("неверный json: %w", err)
		http.Error(writer, "неверный json", http.StatusBadRequest)
		return
	}

	tokensPair, err := handler.AuthenticationService.RefreshToken(
		request.Context(),
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
