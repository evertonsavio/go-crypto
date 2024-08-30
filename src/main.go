package main

import (
	"fmt"
	"log"
	"net/http"
)

const port = 8080

type app struct {
	Domain string
}

func main() {
	var app app

	app.Domain = "http://localhost:8080"

	fmt.Printf("Starting server on %s\n", app.Domain)

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
