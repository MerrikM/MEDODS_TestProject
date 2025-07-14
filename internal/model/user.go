package model

type User struct {
	Id       int
	Username string
	Email    string
	Password string
	Roles    []string
}
