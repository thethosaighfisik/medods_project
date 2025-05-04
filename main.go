package main

import (
	"auth_medods/internal/handlers"
	"github.com/go-chi/chi/v5"
        "net/http"
	"auth_medods/internal/config"
	"auth_medods/external/logging"
	"auth_medods/external/storage"
)

func main(){
	cfg := config.MustLoad()
	logging.SetupLogger(cfg.Env)
	log := logging.Get()

	storage.LogStorage(log)
	storage.SetupStorage(cfg.Storage)
		
	db := storage.Get()
	defer db.Close()
	
	handlers.SetupHandlers(log, db, cfg)
	router := chi.NewRouter()

	router.Post("/login", handlers.LoginHandler)
	router.Post("/refresh", handlers.RefreshHandler)
	router.Post("/register", handlers.RegisterHandler)
        
	log.Info("router is running")
	http.ListenAndServe(cfg.HTTPServer.Address, router)

}

//логирование
