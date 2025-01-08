package repository

import (
	"database/sql"
	"github.com/google/uuid"
	"github.com/thegera4/go-htmx-user-mgt-system/pkg/models"
)

// Returns all users from the database.
func GetAllUsers(db *sql.DB) ([]models.User, error) {
	users := []models.User{}
	query := "SELECT * FROM users"
	rows, err := db.Query(query)
	if err != nil { return nil, err }
	defer rows.Close()

	for rows.Next() {
		user := models.User{}
		err := rows.Scan(&user.Id, &user.Name, &user.Email, &user.Password, &user.Name, &user.Category, &user.DOB, &user.Bio, &user.Avatar)
		if err != nil { return nil, err }
		users = append(users, user)
	}

	return users, nil
}

// Returns a single user from the database with the given user Id.
func GetUserById(db *sql.DB, id int) (models.User, error) {
	user := models.User{}
	query := "SELECT * FROM users WHERE id = ?"
	err := db.QueryRow(query, id).Scan(&user.Id, &user.Name, &user.Email, &user.Password, &user.Name, &user.Category, &user.DOB, &user.Bio, &user.Avatar)
	if err != nil { return user, err }
	user.DOBFormatted = user.DOB.Format("2006-01-02") // Format the date using a friendly format
	return user, nil
}

// Returns a single user from the database with the given user email.
func GetUserByEmail(db *sql.DB, email string) (models.User, error) {
	user := models.User{}
	query := "SELECT * FROM users WHERE email = ?"
	err := db.QueryRow(query, email).Scan(&user.Id, &user.Name, &user.Email, &user.Password, &user.Name, &user.Category, &user.DOB, &user.Bio, &user.Avatar)
	if err != nil { return user, err }
	user.DOBFormatted = user.DOB.Format("2006-01-02") // Format the date using a friendly format
	return user, nil
}

// Inserts a new user into the database.
func CreateUser(db *sql.DB, user models.User) error {
	id, err := uuid.NewUUID()
	if err != nil { return err }

	user.Id = id.String() // Convert the id to string and set it on the user
	stmt, err := db.Prepare("INSERT INTO users (id, name, email, password, category, dob, bio, avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil { return err }
	defer stmt.Close()

	_, err = stmt.Exec(user.Id, user.Name, user.Email, user.Password, user.Category, user.DOB, user.Bio, user.Avatar)
	if err != nil { return err }

	return nil
}

// Updates an existing user in the database with the given user Id.
func UpdateUser(db *sql.DB, id string, user models.User) error {
	_, err := db.Exec("UPDATE users SET name = ?, category = ?, dob = ?, bio = ? WHERE id = ?",
		user.Name, user.Category, user.DOB, user.Bio, id)
	return err
}

// Updates the avatar of an existing user in the database with the given user Id.
func UpdateUserAvatar(db *sql.DB, id string, filePath string) error {
	_, err := db.Exec("UPDATE users SET avatar = ? WHERE id = ?", filePath, id)
	return err
}

// Deletes an existing user from the database with the given user Id.
func DeleteUser(db *sql.DB, id string) error {
	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}