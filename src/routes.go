package main

import "net/http"

type App struct {
	Domain string
}

func (r *App) registerRoutes() {
	http.HandleFunc("/", Home)
}
