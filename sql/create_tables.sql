DROP TABLE IF EXISTS aes;
DROP TABLE IF EXISTS rsa;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
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
);

CREATE TABLE aes (
  id SERIAL,
  key varchar(200) DEFAULT NULL,
  type varchar(45) DEFAULT NULL,
  created_at timestamp without time zone,
  updated_at timestamp without time zone,
  owner_id integer  DEFAULT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE rsa (
  id SERIAL,
  public_key varchar(200) DEFAULT NULL,
  private_key varchar(200) DEFAULT NULL,
  version varchar(45) DEFAULT NULL,
  PRIMARY KEY (id)
);

insert into users (username, email, password, first_name, last_name, created_at, updated_at, disabled, role) values ('admin', 'admin@admin.com', 'admin', 'admin', 'admin', '2022-09-23 00:00:00', '2022-09-23 00:00:00', false, 'ADMIN');
insert into users (username, email, password, first_name, last_name, created_at, updated_at, disabled, role) values ('user', 'user@user.com', 'user', 'user', 'user', '2022-09-23 00:00:00', '2022-09-23 00:00:00', false, 'USER');
