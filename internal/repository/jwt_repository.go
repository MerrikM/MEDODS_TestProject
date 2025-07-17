package repository

import (
	"MEDODS_TestProject/internal"
	"context"
	"fmt"
	"github.com/google/uuid"
	"time"
)

type JWTRepository struct {
	*internal.Database
}

func NewJWTRepository(database *internal.Database) *JWTRepository {
	return &JWTRepository{database}
}

func (repository *JWTRepository) SaveRefreshToken(ctx context.Context, userUUID string, hashedToken string, expireAt time.Time) error {
	query := `INSERT INTO refresh_tokens (id, user_id, token_hash, expire_at) VALUES ($1, $2, $3, $4)`
	id := uuid.New().String()
	_, err := repository.DB.ExecContext(ctx, query, id, userUUID, hashedToken, expireAt)

	if err != nil {
		return fmt.Errorf("ошибка вставки данных в БД: %w", err)
	}

	return nil
}

func (repository *JWTRepository) MarkRefreshTokenUsed(ctx context.Context, refreshTokenID string) error {
	query := `UPDATE refresh_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE`

	result, err := repository.DB.ExecContext(ctx, query, refreshTokenID)
	if err != nil {
		return fmt.Errorf("не удалось обновить рефреш токен: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("не удалось проверить, обновлен ли токен: %v", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("не удалось найти токен для его обновления: %v", err)
	}

	return nil
}
