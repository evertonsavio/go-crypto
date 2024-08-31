package repository

import (
	"database/sql"
	model "go-finder/src/models/user"
)

type Repository interface {
	Connection() *sql.DB
	AllUsers() ([]*model.User, error)
}
