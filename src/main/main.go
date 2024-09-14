package main

import (
	"flag"
	"go-finder/src/main/repository/dbrepo"
	"time"
)

func main() {
	app := App{}

	app.registerRoutes()

	flag.StringVar(&app.DSN, "dsn", "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable timezone=UTC connect_timeout=5", "Postgres connection string")
	flag.StringVar(&app.JWTSecret, "jwt-secret", "secret", "JWT secret")
	flag.StringVar(&app.JWTIssuer, "jwt-issuer", "finder", "JWT issuer")
	flag.StringVar(&app.JWTAudience, "jwt-audience", "finder", "JWT audience")
	flag.StringVar(&app.CookieDomain, "cookie-domain", "localhost", "Cookie domain")
	flag.StringVar(&app.Domain, "domain", "localhost", "Domain name")
	flag.Parse()

	conn, err := app.connectToDB()
	app.handleFatalError("Could not connect to database", err)
	app.DB = &dbrepo.PostgresDBRepo{DB: conn}
	defer app.DB.Connection().Close()

	app.auth = Auth{
		Issuer:        app.JWTIssuer,
		Audience:      app.JWTAudience,
		Secret:        app.JWTSecret,
		TokenExpiry:   time.Minute * 15,
		RefreshExpiry: time.Hour * 24,
		CookiePath:    "/",
		CookieName:    "__Host-refresh-token",
		CookieDomain:  app.CookieDomain,
	}

	err = app.start()
	app.handleFatalError("Could not start server", err)
}
