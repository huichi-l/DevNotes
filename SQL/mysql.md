```sql
-- create db
CREATE DATABASE myDb;

-- add user
CREATE USER 'auth_user'@'locahost' IDENTIFIED BY 'pass123';

-- grant user access to db
GRANT ALL PRIVILEGES ON myDb.* TO 'auth_user'@'localhost' WITH GRANT OPTION;

USE myDb;

-- create table
CREATE TABLE user
(
    id INT NOT NULL
    AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR
    (255) NOT NULL,
    password VARCHAR
    (255) NOT NULL
);

-- insert table
INSERT INTO user
    (email, password)
VALUES
    ('hello@email.com', 'Admin123');

-- alter table column unique
ALTER TABLE user ADD UNIQUE (email);
```
