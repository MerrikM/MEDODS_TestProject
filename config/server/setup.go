package server

import (
	"MEDODS_TestProject/internal"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var (
	DbDriverName       string
	DbConnectionString string
	ServerAddress      string
)

func init() {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	envPath := filepath.Join(wd, "..", ".env")
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf(".env не найден по пути: %s", envPath)
	}

	DbDriverName = os.Getenv("DATABASE_DRIVER")
	DbConnectionString = os.Getenv("DATABASE_CONNECTION_URL")
	ServerAddress = os.Getenv("SERVER_ADDRESS")
}

func SetupDatabase() (*internal.Database, error) {
	database, err := internal.NewDatabaseConnection(DbDriverName, DbConnectionString)
	if err != nil {
		return nil, fmt.Errorf("ошибка подключения: %w", err)
	}
	return database, nil
}

func SetupServer() (*http.Server, *chi.Mux) {
	router := chi.NewRouter()
	server := &http.Server{
		Addr:    ServerAddress,
		Handler: router,
	}

	return server, router
}
