package logging

import (
	"log/slog"
	"os"
)

const (
	envDev = "dev"
	envProd = "prod"
)

var log *slog.Logger

func SetupLogger(env string){
	switch env{
	case envDev:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level : slog.LevelDebug}),)
	case envProd:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level : slog.LevelInfo}),)
	}
}

func Get() *slog.Logger{
	return log
}


