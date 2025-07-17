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

// RefreshToken обновляет refresh-токен
// Выполняет следующие требования к операции refresh:
//  1. Операцию refresh можно выполнить только той парой токенов, которая была выдана вместе.
//  2. Запрещает операцию обновления токенов при изменении User-Agent.
//     При этом, после неудачной попытки выполнения операции, деавторизует пользователя,
//     который попытался выполнить обновление токенов.
//  3. При попытке обновления токенов с нового IP отправляет POST-запрос на заданный webhook
//     с информацией о попытке входа со стороннего IP. Запрещать операцию в данном случае не нужно.
//
// Параметры:
//   - ctx: контекст выполнения (для отмены и таймаутов)
//   - userAgent: информацию о бразуере
//   - ipAddress: ip адрес устройства, с которого был выполнен вход
//   - accessToken: текущий access-токен
//   - refreshToken: текущий refresh-токен
//
// Пример:
//
//	tokensPair, err := handler.AuthenticationService.RefreshToken(
//		request.Context(),
//		"PostmanRuntime/7.44.1",
//		"[::1]:52375",
//		"your token",
//		"your refresh token",
//	 )
//
// Возвращает:
//   - model.TokensPair
//   - ошибку, если не удалось обновить токен.
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

// Logout "деактивирует" пользователя.
// Изменяет статус поля used у refresh-токена и делает его равным true
//
// Параметры:
//   - ctx: контекст выполнения (для отмены и таймаутов)
//   - refreshTokenUUID: UUID рефреш токена из базы даных
//
// Пример:
//
//	err := handler.AuthenticationService.Logout(ctx, "your refresh token uuid")
//
// Возвращает:
//   - ошибку, если не удалось изменить поле used
func (service *AuthenticationService) Logout(ctx context.Context, refreshTokenUUID string) error {
	err := service.JWTRepository.MarkRefreshTokenUsedByUUID(ctx, refreshTokenUUID)
	if err != nil {
		return fmt.Errorf("не удалось использовать токен: %w", err)
	}
	return nil
}
