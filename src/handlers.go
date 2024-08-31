package main

import (
	"encoding/json"
	"go-finder/src/models"
	"go-finder/src/utils"
	"net/http"
)

func Home(w http.ResponseWriter, r *http.Request) {

	/* if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	} */

	var payload = struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Version string `json:"version"`
	}{
		Status:  "success",
		Message: "Welcome to the Go Finder API",
		Version: "1.0.0",
	}

	jsonResponse, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func Serial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var serialData []models.SerialData

	data := models.SerialData{
		ID:        "1",
		Timestamp: "2020-01-01T12:00:00Z",
		Type:      "BLE",
		Rssi:      -50,
		Snr:       10,
		Mac:       "00:11:22:33:44:55",
		Message:   "Hello, World!",
	}

	serialData = append(serialData, data)

	response := utils.JSONResponse{}
	_ = response.WriteJSON(w, http.StatusOK, serialData)
}

func (app *App) User(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	response := utils.JSONResponse{}

	users, err := app.DB.AllUsers()
	if err != nil {
		_ = response.ErrorJson(w, err, http.StatusBadRequest)
		return
	}

	_ = response.WriteJSON(w, http.StatusOK, users)
}
