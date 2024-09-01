package main

import (
	"fmt"
	"go-finder/src/main/repository"
	"log"
	"net/http"
)

const port = 8080

/*
App struct represents the application
@Domain: Domain name
@DSN: Data Source Name
*/
type App struct {
	Domain       string
	DSN          string
	DB           repository.Repository
	auth         Auth
	JWTSecret    string
	JWTIssuer    string
	JWTAudience  string
	CookieDomain string
}

func (app *App) start() error {
	log.Printf("Server started at %s:%d", app.Domain, port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func (app *App) registerRoutes() {
	http.Handle("/", app.enableCORS(app.AuthRequired(http.HandlerFunc(app.GET(Home)))))
	http.Handle("/serial", app.enableCORS(http.HandlerFunc(Serial)))
	http.Handle("/user", app.enableCORS(http.HandlerFunc(app.User)))
	http.Handle("/login", app.enableCORS(http.HandlerFunc(app.Authenticate)))
	http.Handle("/refresh", app.enableCORS(http.HandlerFunc(app.Refresh)))
	http.Handle("/logout", app.enableCORS(http.HandlerFunc(app.Logout)))
}

func (app *App) handleFatalError(errorMessage string, err error) {
	if err != nil {
		log.Fatalf("%s: %s", errorMessage, err)
	}
}

// MIDDLEWARES

// CORS
func (app *App) enableCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://locahost:3000")

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

// GET
func (app *App) GET(f func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}
		f(w, r)
	}
}

// AUTH
func (app *App) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, err := app.auth.GetTokenFromHeaderAndVerify(w, r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Call the next request handler
		next.ServeHTTP(w, r)
	})
}
