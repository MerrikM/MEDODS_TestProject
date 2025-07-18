package handler

import (
	"MEDODS_TestProject/internal/model"
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

// CurrentUserResponse содержит строку с GUID(UUID) пользователя
// swagger:model
type CurrentUserResponse struct {
	UserGUID string `json:"userGUID" example:"123e4567-e89b-12d3-a456-426614174000"`
}

// RefreshTokenRequest содержит refresh токен в json формате
// swagger:model
type RefreshTokenRequest struct {
	// Refresh токен
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	RefreshToken string `json:"refreshToken"`
}

// LogoutResponse содержит строку с сообщением
// swagger:model
type LogoutResponse struct {
	// Сообщение о результате операции
	// example: выполнен выход из аккаунта
	Message string
}

func NewAuthenticationHandler(authenticationService *service.AuthenticationService) *AuthenticationHandler {
	return &AuthenticationHandler{authenticationService}
}

// GetTokens генерирует и возвращает новую пару access/refresh токенов
// @Summary Генерация токенов
// @Description Создает новую пару JWT-токенов и сохраняет refresh-токен в БД. Пример запроса: GET /api-auth/get-tokens?guid=123e4567-e89b-12d3-a456-426614174000
// @Tags Authentication
// @Accept json
// @Produce json
// @Param guid query string true "GUID (UUID) пользователя" example:"123e4567-e89b-12d3-a456-426614174000"
// @Success 200 {object} model.TokensPair "успешный ответ" example:`{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "refresh_token": "vcSi0369y1I62wOpxZFpgZ......"}`
// @Failure 400 {string} string "невалидный или отсутствующий GUID"
// @Failure 500 {string} string "ошибка генерации токенов"
// @Failure 500 {string} string "ошибка сохранения refresh-токена"
// @Security ApiKeyAuth
// @Router /get-tokens [get]
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

	response := &model.TokensPair{
		AccessToken:  tokensPair.AccessToken,
		RefreshToken: tokensPair.RefreshToken,
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}

// GetCurrentUsersUUID godoc
// @Summary Получение GUID (UUID) пользователя
// @Description Извлекает GUID (UUID) пользователя из JWT-токена. Пример запроса: GET /api-auth/me с заголовком Authorization: Bearer <access_token>
// @Tags Authentication
// @Produce json
// @Param Authorization header string true "Bearer токен" default(Bearer <access_token>)
// @Success 200 {object} CurrentUserResponse "Успешный ответ" example:`{"user_guid": "123e4567-e89b-12d3-a456-426614174000"}`
// @Failure 401 {string} string "Пользователь не авторизован или токен недействителен" example:"не авторизован"
// @Security ApiKeyAuth
// @Router /me [get]
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

// RefreshToken обновляет access и refresh токены
// @Summary Обновление токенов
// @Description Обновляет пару JWT-токенов по refresh-токену с проверкой IP и User-Agent. Пример запроса: POST /api-auth/refresh-token с заголовком Authorization: Bearer <access_token> и телом {"refresh_token": "<refresh_token>"}
// @Tags Authentication
// @Accept json
// @Produce json
// @Param Authorization header string true "Access токен" default(Bearer <access_token>)
// @Param request body RefreshTokenRequest true "Refresh токен в теле запроса" example:`{"refresh_token": "vcSi0369y1I62wOpxZFpgZ......"}`
// @Success 200 {object} model.TokensPair "успешное обновление токенов" example:`{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "refresh_token": "vcSi0369y1I62wOpxZFpgZ......"}`
// @Failure 400 {string} string "неверный JSON в теле запроса" example:"неверный json"
// @Failure 401 {string} string "пустой или неверный заголовок Authorization" example:"пустой или неверный заголовок Authorization"
// @Failure 401 {string} string "не удалось обновить токены" example:"не удалось обновить токены"
// @Security ApiKeyAuth
// @Router /refresh-token [post]
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

	response := &model.TokensPair{
		AccessToken:  tokensPair.AccessToken,
		RefreshToken: tokensPair.RefreshToken,
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(&response)
}

// Logout godoc
// @Summary Выход из аккаунта
// @Description Инвалидирует refresh-токен и завершает сеанс пользователя. Пример запроса: POST /api-auth/logout с заголовком Authorization: Bearer <access_token>
// @Tags Authentication
// @Produce json
// @Param Authorization header string true "Bearer токен" default(Bearer <access_token>)
// @Success 200 {object} LogoutResponse "Успешный выход" example:`{"message": "выполнен выход из аккаунта"}`
// @Failure 400 {string} string "ошибка запроса" example:"ошибка запроса"
// @Failure 401 {string} string "пользователь не авторизован" example:"не авторизован"
// @Security ApiKeyAuth
// @Router /logout [post]
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
