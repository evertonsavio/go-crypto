package models

type SerialData struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Mac       string `json:"mac"`
	Message   string `json:"message"`
}
