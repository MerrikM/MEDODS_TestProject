package internal

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"log"
)

type Database struct {
	*sqlx.DB
}

func NewDatabaseConnection(dbDriver string, dbConnectionStr string) (*Database, error) {
	database, err := sqlx.Connect(dbDriver, dbConnectionStr)
	if err != nil {
		return nil, fmt.Errorf("ошибка подключения к БД: %w", err)
	}

	if err := database.Ping(); err != nil {
		return nil, fmt.Errorf("ошибка пинга БД: %w", err)
	}

	log.Println("Подключение к БД успешно выполнено")
	return &Database{
		database,
	}, nil
}

func (db *Database) Close() error {
	err := db.DB.Close()
	if err != nil {
		return fmt.Errorf("ошибка закрытия соединения с БД: %w", err)
	}

	return nil
}
