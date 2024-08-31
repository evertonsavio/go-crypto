package repository

import (
	"database/sql"
	"go-finder/src/main/models/user"
)

type Repository interface {
	Connection() *sql.DB
	AllUsers() ([]*user.User, error)
}
