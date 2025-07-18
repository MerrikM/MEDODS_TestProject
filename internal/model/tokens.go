package model

import "time"

type RefreshToken struct {
	UUID      string    `db:"uuid"`
	UserUUID  string    `db:"user_uuid"`
	TokenHash string    `db:"token_hash"`
	ExpireAt  time.Time `db:"expire_at"`
	Used      bool      `db:"used"`
	UserAgent string    `db:"user_agent"`
	IpAddress string    `db:"ip_address"`
}

// TokensPair содержит пару access и refresh токенов
// swagger:model
type TokensPair struct {
	// Access токен (JWT)
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken string `json:"accessToken"`

	// Refresh токен (для получения новой пары)
	// example: vcSi0369y1I62wOpxZFpgZ...
	RefreshToken string `json:"refreshToken"`
}
