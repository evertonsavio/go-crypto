package dbrepo

import (
	"context"
	"database/sql"
	"go-finder/src/main/models/user"
	"time"
)

type PostgresDBRepo struct {
	DB *sql.DB
}

const dbTimeout = time.Second * 3

func (m *PostgresDBRepo) Connection() *sql.DB {
	return m.DB
}

func (m *PostgresDBRepo) AllUsers() ([]*user.User, error) {
	// If the interaction with the database takes more than 3 seconds, the context will be canceled
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `
		SELECT
			id, username, email, password, 
			first_name, last_name, role
		FROM users
		ORDER BY
			id ASC
	`

	rows, err := m.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*user.User
	for rows.Next() {
		user := new(user.User)
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.Password,
			&user.FirstName,
			&user.LastName,
			&user.Role,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func (m *PostgresDBRepo) GetUserByEmail(email string) (*user.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `
		SELECT
			id, username, email, password, 
			first_name, last_name, role
		FROM users
		WHERE email = $1
	`

	row := m.DB.QueryRowContext(ctx, query, email)

	user := new(user.User)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.Role,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}
