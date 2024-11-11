CREATE DATABASE IF NOT EXISTS authdb;

USE authdb;

CREATE TABLE Users (
	id INT NOT NULL AUTO_INCREMENT,
	email VARCHAR(20) NOT NULL,
	password_digest VARCHAR(255) NOT NULL,
	salt VARCHAR(20) NOT NULL,
	active BOOLEAN DEFAULT TRUE,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id)
);

CREATE TABLE Permissions (
	id INT NOT NULL AUTO_INCREMENT,
	name VARCHAR(20) NOT NULL,
	--the targeted app
	audience TINYTEXT NOT NULL,
	description TINYTEXT,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id)
);

CREATE TABLE UsersPermissions (
	id INT NOT NULL AUTO_INCREMENT,
	user_id INT NOT NULL,
	permission_id INT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES Users(id),
	FOREIGN KEY (permission_id) REFERENCES Permissions(id),
	PRIMARY KEY (id)

);

--Password: Newspaper123!
INSERT INTO Users
(email, password_digest, salt) VALUES (
	'test@newspaper.com', 
	'bbe6dc7840a914d1be8b7aaadfd963d084a9ed9bb1c4a7020062eb170ccad11b28c55341956baca23cdc5c5873ab0600199463e8933206ed8affdff213fcfab7',
	'Li8J7gHu9'
);

INSERT INTO Permissions 
(name, audience) VALUES
('TestUser', '127.0.0.1:3000');

INSERT INTO UsersPermissions 
(user_id, permission_id) VALUES (1, 1);

