package model

import "time"

type RefreshToken struct {
	UUID      string
	UserUUID  string
	TokenHash string
	ExpireAt  time.Time
	Used      bool
}

type TokensPair struct {
	AccessToken  string
	RefreshToken string
}
