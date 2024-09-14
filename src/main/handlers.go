package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"go-finder/src/main/models"
	"go-finder/src/main/utils"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
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

func Serial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var serialData []models.SerialData

	data := models.SerialData{
		ID:        "1",
		Timestamp: "2020-01-01T12:00:00Z",
		Type:      "SERIAL",
		Mac:       "00:11:22:33:44:55",
		Message:   "Hello, Serial!",
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

///////////////////RSA///AES////////////////////////

// Create RSA key pair
func CheckError(e error) {
	if e != nil {
		fmt.Println(e.Error)
	}
}

type Tuple struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type SecretMessage struct {
	BlackKey  string  `json:"blackKey"`
	WhiteKey  string  `json:"whiteKey"`
	WhiteList []Tuple `json:"whiteList"`
}

func (app *App) RSA(w http.ResponseWriter, r *http.Request) {
	//privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	//CheckError(err)
	//READ PRIVATE KEY BEGIN
	privateKeyFile, err := os.Open("./assets/private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	CheckError(err)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//READ PRIVATE KEY END
	//fmt.Println("Private Key : ", privateKey)

	/* pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close() */
	//defer pemPrivateFile.Close()

	/* publicKey := privateKey.PublicKey
	pemPrivateFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPublicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
	}

	err = pem.Encode(pemPrivateFile, pemPublicBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close() */
	publicKeyFile, err := os.Open("./assets/public_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPubfileinfo, _ := publicKeyFile.Stat()
	sizePub := pemPubfileinfo.Size()
	pembytesPub := make([]byte, sizePub)
	bufferPub := bufio.NewReader(publicKeyFile)
	_, err = bufferPub.Read(pembytesPub)
	CheckError(err)
	dataPub, _ := pem.Decode([]byte(pembytesPub))
	publicKeyFile.Close()

	importedPublicKey, err := x509.ParsePKCS1PublicKey(dataPub.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	publicKey := *importedPublicKey

	secretMessage, err := json.Marshal(SecretMessage{
		BlackKey: "6np7S34PLrOxV1IXd4GKA9d5jtVHIgYZwY2CMY9KxYk=",
		WhiteKey: "MzA/NghRZwaXr0zpS3i4hyPtoCj8vPzZ/NDSe7TTmuU=",
		WhiteList: []Tuple{
			{From: "*", To: "*"},
		},
	})
	CheckError(err)
	fmt.Println(string(secretMessage))
	encryptedMessage := RSA_OAEP_Encrypt(string(secretMessage), publicKey)

	response := struct {
		Payload  string `json:"payload"`
		WhiteKey string `json:"whiteKey"`
	}{
		Payload:  encryptedMessage,
		WhiteKey: "MzA/NghRZwaXr0zpS3i4hyPtoCj8vPzZ/NDSe7TTmuU=",
	}

	RSA_OAEP_Decrypt(encryptedMessage, *privateKey)
	var jsonResponse utils.JSONResponse
	jsonResponse.WriteJSON(w, http.StatusOK, response)
}

func RSA_OAEP_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	CheckError(err)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_OAEP_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)

	CheckError(err)
	fmt.Println("Plaintext:", string(plaintext))
	return string(plaintext)
}

// //////////////AES////////////////////////////////////////
func (app *App) AES(w http.ResponseWriter, r *http.Request) {
	// Generate a random 32 byteString key
	secretKey := make([]byte, 32)
	_, err := rand.Read(secretKey)
	if err != nil {
		panic(err)
	}

	// cast secretKey to hex string
	hexSecretKey := base64.StdEncoding.EncodeToString(secretKey)

	// decode hex string back to byteString
	decodedSecret, err := base64.StdEncoding.DecodeString(hexSecretKey)
	if err != nil {
		panic(err)
	}

	// This will successfully encrypt & decrypt
	ciphertext1 := encrypt("This is some sensitive information", secretKey)
	fmt.Printf("Encrypted ciphertext 1: %x \n", ciphertext1)

	plaintext1 := decrypt(ciphertext1, decodedSecret)
	fmt.Printf("Decrypted plaintext 1: %s \n", plaintext1)

	// This will successfully encrypt & decrypt as well.
	ciphertext2 := encrypt("SUCCESS", secretKey)
	fmt.Printf("Encrypted ciphertext 2: %x \n", ciphertext2)

	plaintext2 := decrypt(ciphertext2, decodedSecret)
	fmt.Printf("Decrypted plaintext 2: %s \n", plaintext2)

	var jsonResponse utils.JSONResponse
	jsonResponse.WriteJSON(w, http.StatusOK, plaintext2)
}

func encrypt(plaintext string, secretKey []byte) string {
	aes, err := aes.NewCipher(secretKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}

func decrypt(ciphertext string, secretKey []byte) string {
	aes, err := aes.NewCipher(secretKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		panic(err)
	}

	return string(plaintext)
}

/* func rsaConfigSetup(rsaPrivateKeyLocation, rsaPublicKeyLocation string) (*rsa.PrivateKey, error) {
	if rsaPrivateKeyLocation == "" {
		log.Print("No RSA Key given, generating temp one")
		return generatePrivateKey(4096)
	}

	priv, err := os.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.Print("No RSA private key found, generating temp one")
		return generatePrivateKey(4096)
	}

	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		log.Printf("RSA private key is of the wrong type :%s", privPem.Type)
	}
	privPemBytes = privPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			log.Printf("Unable to parse RSA private key, generating a temp one :%s", err.Error())
			return generatePrivateKey(4096)
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Printf("Unable to parse RSA private key, generating a temp one : %s", err.Error())
		return generatePrivateKey(4096)
	}

	pub, err := os.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		log.Print("No RSA public key found, generating temp one")
		return generatePrivateKey(4096)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		log.Printf("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public :rsa public key not in pem format: %s", rsaPublicKeyLocation)
		return generatePrivateKey(4096)
	}
	if pubPem.Type != "RSA PUBLIC KEY" {
		log.Printf("RSA public key is of the wrong type, Pem Type :%s", pubPem.Type)
		return generatePrivateKey(4096)
	}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		log.Printf("Unable to parse RSA public key, generating a temp one: %s", err.Error())
		return generatePrivateKey(4096)
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		log.Printf("Unable to parse RSA public key, generating a temp one: %s", err.Error())
		return generatePrivateKey(4096)
	}

	privateKey.PublicKey = *pubKey

	return privateKey, nil
}

// generatePrivateKey returns a new RSA key of bits length
func generatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	log.Printf("Failed to generate signing key :%s", err.Error())
	return key, err
}
*/
