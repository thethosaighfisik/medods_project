package storage

import (
	"fmt"
	"database/sql"
	"log/slog"
	
	"auth_medods/internal/config"

	_ "github.com/lib/pq"
)

var db *sql.DB
var log *slog.Logger

func SetupStorage(storage config.Storage){
	
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", storage.Host, storage.Port, storage.User, storage.Password, storage.DBName, storage.SSLMode))
	if err != nil{
		log.Error("error:", err)
	}

	log.Info("Setup db is successful")
}

func LogStorage(logger *slog.Logger){
	log = logger
}

func Get() *sql.DB{
	return db
}
