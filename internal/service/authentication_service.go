package service

import (
	"MEDODS_TestProject/config"
	"MEDODS_TestProject/internal/model"
	"MEDODS_TestProject/internal/notifier"
	"MEDODS_TestProject/internal/repository"
	"MEDODS_TestProject/internal/security"
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

type AuthenticationService struct {
	*repository.JWTRepository
	*config.Config
	*security.JWTService
}

func NewAuthenticationService(repo *repository.JWTRepository, cfg *config.Config, service *security.JWTService) *AuthenticationService {
	return &AuthenticationService{repo, cfg, service}
}

func (service *AuthenticationService) RefreshToken(ctx context.Context, userAgent string, ipAddress string, accessToken string, refreshToken string) (*model.TokensPair, error) {
	claims, err := security.ValidateJWT(accessToken, []byte(service.Config.JWT.SecretKey))
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
	if storedRefreshToken.IpAddress != ipAddress {
		log.Printf("обнаружен вход с нового устройства, отправка webhook")
		go func() {
			if err := notifier.NotifyWebhook(service.Config.Webhook.URL, userUUID, ipAddress, storedRefreshToken.IpAddress); err != nil {
				log.Printf("ошибка отправки webhook: %v", err)
			}
		}()
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedRefreshToken.TokenHash), []byte(refreshToken))
	if err != nil {
		return nil, fmt.Errorf("невалидный токен: %w", err)
	}

	if err := service.JWTRepository.MarkRefreshTokenUsedByUUID(ctx, refreshTokenUUID); err != nil {
		return nil, fmt.Errorf("не удалось использовать токен: %w", err)
	}

	tokensPair, newRefreshToken, err := service.JWTService.GenerateAccessRefreshTokens(userUUID)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации токенов: %w", err)
	}

	newRefreshToken.UserAgent = userAgent
	newRefreshToken.IpAddress = ipAddress
	err = service.JWTRepository.SaveRefreshToken(ctx, newRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("не удалось сохранить рефреш токен: %w", err)
	}

	return tokensPair, nil
}

func (service *AuthenticationService) Logout(ctx context.Context, refreshTokenUUID string) error {
	err := service.JWTRepository.MarkRefreshTokenUsedByUUID(ctx, refreshTokenUUID)
	if err != nil {
		return fmt.Errorf("не удалось использовать токен: %w", err)
	}
	return nil
}
