package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go-finder/src/main/utils"
	"net/http"

	"github.com/capsule-software/capsule"
	"github.com/golang-jwt/jwt/v5"
)

func Home(w http.ResponseWriter, r *http.Request) {

	var payload = struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Version string `json:"version"`
	}{
		Status:  "success",
		Message: "Welcome to GOLANG Server API",
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

func (app *App) RSAKeys(w http.ResponseWriter, r *http.Request) {
	rsa := new(capsule.RSA_OAEP)
	privateKey, err := rsa.LoadPrivateKey("./assets/private_key.pem")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	publicKey, err := rsa.LoadPublicKey("./assets/public_key.pem")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)

	privateKeyString := string(privateKeyBytes)
	publicKeyString := string(publicKeyBytes)

	var response = struct {
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}{
		PublicKey:  publicKeyString,
		PrivateKey: privateKeyString,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app *App) AESKeys(w http.ResponseWriter, r *http.Request) {
	aes := new(capsule.AES_GCM)
	key := aes.Generate32BytesBase64Key()

	var response = struct {
		Key string `json:"key"`
	}{
		Key: key,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app *App) Authenticate(w http.ResponseWriter, r *http.Request) {

	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var jsonResponse utils.JSONResponse
	err := jsonResponse.ReadJson(w, r, &requestPayload)
	if err != nil {
		jsonResponse.ErrorJson(w, err, http.StatusBadRequest)
		return
	}

	user, err := app.DB.GetUserByEmail(requestPayload.Email)
	if err != nil {
		jsonResponse.ErrorJson(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}
	valid, err := user.CheckPassword(requestPayload.Password)
	if err != nil || !valid {
		jsonResponse.ErrorJson(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	u := jwtUser{
		ID:        user.ID,
		Username:  user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Role:      user.Role,
	}

	tokenPair, err := app.auth.GenerateTokenPair(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshCookie := app.auth.GetRefreshCookie(tokenPair.RefreshToken)
	http.SetCookie(w, refreshCookie)

	jsonResponse.WriteJSON(w, http.StatusAccepted, tokenPair)
}

// Refresh token
func (app *App) Refresh(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		if cookie.Name == app.auth.CookieName {
			claims := &Claims{}
			refreshtoken := cookie.Value

			var jsonResponse utils.JSONResponse

			_, err := jwt.ParseWithClaims(refreshtoken, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(app.auth.Secret), nil
			})
			if err != nil {
				jsonResponse.ErrorJson(w, errors.New("unauthorized"), http.StatusBadRequest)
				return
			}

			//userId, err := strconv.Atoi(claims.Subject)
			subject := claims.Subject
			dst := make([]byte, base64.StdEncoding.DecodedLen(len(subject)))
			n, err := base64.StdEncoding.Decode(dst, []byte(subject))
			if err != nil {
				fmt.Println("decode error:", err)
				return
			}
			// [:n] is used to trim the extra 0 bytes from the decoded slice
			userEmail := string(dst[:n])

			user, err := app.DB.GetUserByEmail(userEmail)
			if err != nil {
				jsonResponse.ErrorJson(w, errors.New("unknown user"), http.StatusBadRequest)
				return
			}

			u := jwtUser{
				ID:        user.ID,
				Username:  user.Username,
				FirstName: user.FirstName,
				LastName:  user.LastName,
				Email:     user.Email,
				Role:      user.Role,
			}

			tokenPair, err := app.auth.GenerateTokenPair(&u)
			if err != nil {
				jsonResponse.ErrorJson(w, errors.New("error generating tokens"), http.StatusInternalServerError)
				return
			}

			jsonResponse.WriteJSON(w, http.StatusOK, tokenPair)
		}
	}
}

// logout
func (app *App) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, app.auth.GetExpiredRefreshCookie())
	w.WriteHeader(http.StatusAccepted)
}
