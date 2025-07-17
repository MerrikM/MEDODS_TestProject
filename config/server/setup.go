package server

import (
	"MEDODS_TestProject/internal"
	"fmt"
	"github.com/go-chi/chi/v5"
	"net/http"
)

func SetupDatabase(dbDriverName string, DbConnectionString string) (*internal.Database, error) {
	database, err := internal.NewDatabaseConnection(dbDriverName, DbConnectionString)
	if err != nil {
		return nil, fmt.Errorf("ошибка подключения: %w", err)
	}
	return database, nil
}

func SetupServer(serverAddress string) (*http.Server, *chi.Mux) {
	router := chi.NewRouter()
	server := &http.Server{
		Addr:    serverAddress,
		Handler: router,
	}

	return server, router
}
