package main

import (
	"fmt"
	"log"
	"net/http"
)

const port = 8080

type App struct {
	Domain string
}

func (app *App) start() error {
	log.Printf("Server started at %s:%d", app.Domain, port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

// CORS
func (app *App) enableCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://*")

		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, X-CSRF-Token, Authorization")
			return
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func (app *App) registerRoutes() {
	http.Handle("/", app.enableCORS(http.HandlerFunc(Home)))
	http.Handle("/serial", app.enableCORS(http.HandlerFunc(Serial)))
}
