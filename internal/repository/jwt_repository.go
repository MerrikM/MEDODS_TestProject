package repository

import (
	"MEDODS_TestProject/internal"
	"MEDODS_TestProject/internal/model"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type JWTRepository struct {
	*internal.Database
}

func NewJWTRepository(database *internal.Database) *JWTRepository {
	return &JWTRepository{database}
}

func (repository *JWTRepository) SaveRefreshToken(ctx context.Context, refreshToken *model.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (uuid, user_uuid, token_hash, expire_at, used) VALUES ($1, $2, $3, $4, $5)`

	_, err := repository.DB.ExecContext(ctx, query,
		refreshToken.UUID,
		refreshToken.UserUUID,
		refreshToken.TokenHash,
		refreshToken.ExpireAt,
		refreshToken.Used,
	)

	if err != nil {
		return fmt.Errorf("ошибка вставки данных в БД: %w", err)
	}

	return nil
}

func (repository *JWTRepository) MarkRefreshTokenUsedByUUID(ctx context.Context, refreshTokenUUID string) error {
	query := `UPDATE refresh_tokens SET used = TRUE WHERE uuid = $1 AND used = FALSE`

	result, err := repository.DB.ExecContext(ctx, query, refreshTokenUUID)
	if err != nil {
		return fmt.Errorf("не удалось обновить рефреш токен: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("не удалось проверить, обновлен ли токен: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("не удалось найти токен для его обновления: %w", err)
	}

	return nil
}

func (repository *JWTRepository) FindByUUID(ctx context.Context, refreshTokenUUID string) (*model.RefreshToken, error) {
	query := `SELECT uuid, user_uuid, token_hash, expire_at, used FROM refresh_tokens WHERE uuid = $1`

	refreshToken := &model.RefreshToken{}

	err := repository.DB.QueryRowContext(ctx, query, refreshTokenUUID).Scan(
		&refreshToken.UUID,
		&refreshToken.UserUUID,
		&refreshToken.TokenHash,
		&refreshToken.ExpireAt,
		&refreshToken.Used,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("токен не был найден: %w", err)
		}
		return nil, fmt.Errorf("ошибка при выполнении запроса: %w", err)
	}

	return refreshToken, nil
}
