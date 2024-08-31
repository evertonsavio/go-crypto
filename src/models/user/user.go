package user

/*
  id SERIAL,
  username varchar(45) DEFAULT NULL,
  email varchar(200) DEFAULT NULL,
  password varchar(200) DEFAULT NULL,
  first_name varchar(45) DEFAULT NULL,
  last_name varchar(45) DEFAULT NULL,
  created_at timestamp without time zone,
  updated_at timestamp without time zone,
  disabled boolean DEFAULT NULL,
  role varchar(45) DEFAULT NULL,
  PRIMARY KEY (id)
*/

// User is a struct that represents the user model
type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Disabled  bool   `json:"disabled"`
	Role      string `json:"role"`
}
