package repository

import (
	"MEDODS_TestProject/internal"
	"MEDODS_TestProject/internal/model"
	"database/sql"
	"errors"
	"fmt"
	"log"
)

type UserRepository struct {
	*internal.Database
}

func NewUserRepository(database *internal.Database) *UserRepository {
	return &UserRepository{database}
}

func (repository *UserRepository) Register(user *model.User) (*model.User, error) {
	user.Roles = []string{"ROLE_USER"}

	query := `INSERT INTO users (username, email, password)
			  VALUES (:username, :email, :password)
			  RETURNING id`

	err := repository.DB.QueryRowx(query, user).Scan(&user.Id)
	if err != nil {
		return nil, fmt.Errorf("ошибка вставки пользователя: %w", err)
	}

	return user, nil
}

func (repository *UserRepository) FindByEmail(email string) bool {
	var user model.User

	query := `SELECT * FROM users WHERE email = $1`
	err := repository.DB.Get(&user, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		log.Printf("ошибка выполнения запроса: %w", err)
		return false
	}

	return true
}
