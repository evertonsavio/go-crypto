package main

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Auth struct {
	Issuer        string
	Audience      string
	Secret        string
	TokenExpiry   time.Duration
	RefreshExpiry time.Duration
	CookieDomain  string
	CookiePath    string
	CookieName    string
}

type jwtUser struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

type TokenPairs struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	jwt.RegisteredClaims
	Role  string `json:"rol,omitempty"`
	Email string `json:"ema,omitempty"`
}

func (auth *Auth) GenerateTokenPair(user *jwtUser) (*TokenPairs, error) {
	// Create a token
	access_token := jwt.New(jwt.SigningMethodHS256)

	data := []byte(user.Email)
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	subject := string(dst)

	// Set the claims
	claims := access_token.Claims.(jwt.MapClaims)
	claims["sub"] = subject //fmt.Sprint(user.ID)
	claims["aud"] = auth.Audience
	claims["iss"] = auth.Issuer
	claims["iat"] = time.Now().Unix()

	// Set the expiry
	claims["exp"] = time.Now().Add(auth.TokenExpiry).Unix()

	// Sign the token
	signedAccessToken, err := access_token.SignedString([]byte(auth.Secret))
	if err != nil {
		return &TokenPairs{}, err
	}

	// Create a refresh token and set claims
	refresh_token := jwt.New(jwt.SigningMethodHS256)
	refreshTokenClaims := refresh_token.Claims.(jwt.MapClaims)

	// Set the claims
	refreshTokenClaims["sub"] = subject //fmt.Sprint(user.ID)
	refreshTokenClaims["iat"] = time.Now().Unix()

	// Set the expiry/
	refreshTokenClaims["exp"] = time.Now().Add(auth.RefreshExpiry).Unix()

	// Sign the refresh token
	signedRefreshToken, err := refresh_token.SignedString([]byte(auth.Secret))
	if err != nil {
		return &TokenPairs{}, err
	}

	var tokenPairs = TokenPairs{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}

	return &tokenPairs, nil
}

func (auth *Auth) GetRefreshCookie(refreshToken string) *http.Cookie {
	return &http.Cookie{
		Name:     auth.CookieName,
		Path:     auth.CookiePath,
		Value:    refreshToken,
		Expires:  time.Now().Add(auth.RefreshExpiry),
		MaxAge:   int(auth.RefreshExpiry.Seconds()),
		SameSite: http.SameSiteStrictMode,
		Domain:   auth.CookieDomain,
		HttpOnly: true,
		Secure:   true,
	}
}

func (auth *Auth) GetExpiredRefreshCookie() *http.Cookie {
	return &http.Cookie{
		Name:     auth.CookieName,
		Path:     auth.CookiePath,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
		Domain:   auth.CookieDomain,
		HttpOnly: true,
		Secure:   true,
	}
}
