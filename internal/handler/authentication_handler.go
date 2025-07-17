package handler

import (
	"MEDODS_TestProject/internal/repository"
	"MEDODS_TestProject/internal/security"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type AuthenticationHandler struct {
	*repository.JWTRepository
}

type CurrentUserResponse struct {
	UserGUID string `json:"userGUID"`
}

type TokensResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

const accessTokenTTL = time.Hour

func NewAuthenticationHandler(jwtRepository *repository.JWTRepository) *AuthenticationHandler {
	return &AuthenticationHandler{jwtRepository}
}

func (handler *AuthenticationHandler) GetTokens(writer http.ResponseWriter, request *http.Request) {
	guid := request.URL.Query().Get("guid")

	tokensPair, hashedToken, _, err := security.GenerateAccessRefreshTokens(guid)
	if err != nil {
		log.Printf("ошибка генерации токенов: %v", err)
		http.Error(writer, "ошибка генерации токенов", http.StatusInternalServerError)
		return
	}
	expireAt := time.Now().Add(accessTokenTTL)
	err = handler.JWTRepository.SaveRefreshToken(request.Context(), guid, hashedToken, expireAt)
	if err != nil {
		log.Printf("ошибка сохранения рефреш токена: %v", err)
		http.Error(writer, "ошибка сохранения токена", http.StatusInternalServerError)
		return
	}

	response := &TokensResponse{
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
