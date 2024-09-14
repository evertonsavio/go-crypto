package user

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User is a struct that represents the user model
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Disabled  bool      `json:"disabled"`
	Role      string    `json:"role"`
}

func (u *User) SetCreatedAt() {
	u.CreatedAt = time.Now()
}

func (u *User) SetUpdatedAt() {
	u.UpdatedAt = time.Now()
}

func (u *User) CheckPassword(password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}
