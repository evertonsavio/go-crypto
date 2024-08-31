package main

import (
	"flag"
	"go-finder/src/repository/dbrepo"
)

func main() {
	var app App

	app.Domain = "http://localhost"
	app.registerRoutes()

	flag.StringVar(&app.DSN, "dsn", "host=localhost port=5432 user=postgres password=postgres dbname=finder sslmode=disable timezone=UTC connect_timeout=5", "Postgres connection string")
	flag.Parse()

	conn, err := app.connectToDB()
	app.handleFatalError("Could not connect to database", err)
	app.DB = &dbrepo.PostgresDBRepo{DB: conn}
	defer app.DB.Connection().Close()

	err = app.start()
	app.handleFatalError("Could not start server", err)
}
