package main

import (
	"MEDODS_TestProject/config"
	"MEDODS_TestProject/config/server"
	"MEDODS_TestProject/internal/handler"
	"MEDODS_TestProject/internal/repository"
	"MEDODS_TestProject/internal/security"
	"MEDODS_TestProject/internal/service"
	"context"
	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.LoadConfig("../config.yaml")
	if err != nil {
		log.Fatalf("ошибка загрузки конфигурации: %v", err)
	}

	database, err := server.SetupDatabase(cfg.Database.Driver, cfg.Database.ConnectionString)
	if err != nil {
		log.Fatalf("не удалось подключиться к БД: %v", err)
	}
	defer database.Close()

	srv, router := server.SetupServer(cfg.Server.Port)

	jwtRepository := repository.NewJWTRepository(database)
	jwtService := security.NewJWTService(cfg)
	authenticationService := service.NewAuthenticationService(jwtRepository, cfg, jwtService)
	authenticationHandler := handler.NewAuthenticationHandler(authenticationService)

	router.Route("/api-auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(security.JWTMiddleware([]byte(cfg.JWT.SecretKey), jwtRepository))
			r.Get("/me", authenticationHandler.GetCurrentUsersUUID)
			r.Post("/refresh-token", authenticationHandler.RefreshToken)
			r.Post("/logout", authenticationHandler.Logout)
		})
		r.Group(func(r chi.Router) {
			r.Get("/get-tokens", authenticationHandler.GetTokens)
		})
	})

	runServer(ctx, srv)
}

func runServer(ctx context.Context, server *http.Server) {
	serverErrors := make(chan error, 1)
	go func() {
		log.Println("сервер запущен на " + server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != nil {
			log.Fatalf("ошибка работы сервера: %v", err)
		}
	case sig := <-signalChannel:
		log.Printf("получен сигнал %v остановки работы сервера ", sig)
	}

	shutDownCtx, shutDownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutDownCancel()

	if err := server.Shutdown(shutDownCtx); err != nil {
		log.Printf("ошибка при остановке сервера: %v", err)
	} else {
		log.Println("Сервер успешно остановлен")
	}
}
