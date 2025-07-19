package ports

import (
	"MEDODS_TestProject/internal/model"
	"MEDODS_TestProject/internal/security"
	"context"
)

type JWTRepositoryInterface interface {
	FindByUUID(ctx context.Context, uuid string) (*model.RefreshToken, error)
	MarkRefreshTokenUsedByUUID(ctx context.Context, uuid string) error
	SaveRefreshToken(ctx context.Context, token *model.RefreshToken) error
}

type JWTServiceInterface interface {
	GenerateAccessRefreshTokens(userUUID string) (*model.TokensPair, *model.RefreshToken, error)
	ValidateJWT(tokenString string, secret []byte) (*security.Claims, error)
}
