package main

import (
	"log"
)

func handleError(errorMessage string, err error) {
	if err != nil {
		log.Fatalf("%s: %s", errorMessage, err)
	}
}

func main() {
	var app App

	app.Domain = "http://localhost"
	app.registerRoutes()

	err := app.start()
	handleError("Could not start server", err)
}
