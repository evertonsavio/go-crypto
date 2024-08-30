package main

import (
	"fmt"
	"log"
	"net/http"
)

const port = 8080

func main() {
	var app App

	app.Domain = "http://localhost:8080"

	fmt.Printf("Starting server on %s\n", app.Domain)

	app.registerRoutes()

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
