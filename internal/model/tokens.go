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

type TokensPair struct {
	AccessToken  string
	RefreshToken string
}
