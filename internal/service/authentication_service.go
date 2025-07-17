package service

import (
	"MEDODS_TestProject/internal/model"
	"MEDODS_TestProject/internal/repository"
	"MEDODS_TestProject/internal/security"
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type AuthenticationService struct {
	*repository.JWTRepository
}

var secretKey = []byte("SECRET_KEY=4baeef081535397ee96f810e4c205acc7364f1a9cf94b4508d9a")

func NewAuthenticationService(repo *repository.JWTRepository) *AuthenticationService {
	return &AuthenticationService{repo}
}

func (service *AuthenticationService) RefreshToken(ctx context.Context, userAgent string, accessToken string, refreshToken string) (*model.TokensPair, error) {
	claims, err := security.ValidateJWT(accessToken, secretKey)
	if err != nil {
		return nil, fmt.Errorf("не удалось провалидировать токен: %w", err)
	}

	refreshTokenUUID := claims.RefreshTokenUUID
	userUUID := claims.UserUUID

	storedRefreshToken, err := service.JWTRepository.FindByUUID(ctx, refreshTokenUUID)
	if err != nil {
		return nil, fmt.Errorf("не удалось найти рефреш токен: %w", err)
	}
	if storedRefreshToken.Used == true {
		return nil, fmt.Errorf("токен уже был использован")
	}
	if time.Now().After(storedRefreshToken.ExpireAt) {
		return nil, fmt.Errorf("токен просрочен")
	}
	if storedRefreshToken.UserAgent != userAgent {
		_ = service.JWTRepository.MarkRefreshTokenUsedByUUID(ctx, refreshTokenUUID)
		return nil, fmt.Errorf("обновление токена запрещено. User-Agent был изменен")
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedRefreshToken.TokenHash), []byte(refreshToken))
	if err != nil {
		return nil, fmt.Errorf("невалидный токен: %w", err)
	}

	if err := service.JWTRepository.MarkRefreshTokenUsedByUUID(ctx, refreshTokenUUID); err != nil {
		return nil, fmt.Errorf("не удалось использовать токен: %w", err)
	}

	tokensPair, newRefreshToken, err := security.GenerateAccessRefreshTokens(userUUID)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации токенов: %w", err)
	}

	newRefreshToken.UserAgent = userAgent
	err = service.JWTRepository.SaveRefreshToken(ctx, newRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("не удалось сохранить рефреш токен: %w", err)
	}

	return tokensPair, nil
}
