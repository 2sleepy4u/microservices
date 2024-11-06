CREATE DATABASE IF NOT EXISTS authdb;

USE authdb;

CREATE TABLE Users (
	id int NOT NULL AUTO_INCREMENT,
	email VARCHAR(20),
	password_digest VARCHAR(255),
	salt VARCHAR(20),
	PRIMARY KEY (id)
);
