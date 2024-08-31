package models

// SerialData is a struct that represents the data that comes from serial port
type SerialData struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Rssi      int    `json:"rssi"`
	Snr       int    `json:"snr"`
	Mac       string `json:"mac"`
	Message   string `json:"message"`
}
