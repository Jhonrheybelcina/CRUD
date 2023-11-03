package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	// "github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Shoe struct {
	ID    string  `json:"id,omitempty"`
	Brand string  `json:"brand,omitempty"`
	Model string  `json:"model,omitempty"`
	Size  int     `json:"size,omitempty"`
	Color string  `json:"color,omitempty"`
	Price float64 `json:"price,omitempty"`
}

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("mysql", "root:Jhonrhey#123@tcp(localhost:3306)/gocrud")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		password VARCHAR(255) NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Create the 'shoes' table if it does not exist
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS shoes (
		id INT AUTO_INCREMENT PRIMARY KEY,
		brand VARCHAR(255),
		model VARCHAR(255),
		size INT,
		color VARCHAR(255),
		price DECIMAL(10, 2)
	)`)
	if err != nil {
		panic(err.Error())
	}

	r := mux.NewRouter()

	// Handle protected routes with authenticationMiddleware
	protectedRoutes := r.PathPrefix("/protected").Subrouter()
	protectedRoutes.Use(authenticationMiddleware)

	// Protected routes
	protectedRoutes.HandleFunc("/showAll", GetShoes).Methods("GET")
	protectedRoutes.HandleFunc("/show/{id}", GetShoe).Methods("GET")
	protectedRoutes.HandleFunc("/create", CreateShoe).Methods("POST")
	protectedRoutes.HandleFunc("/update/{id}", UpdateShoe).Methods("PUT")
	protectedRoutes.HandleFunc("/delete/{id}", DeleteShoe).Methods("DELETE")
	protectedRoutes.HandleFunc("/profile/{id}", ViewProfile).Methods("GET")

	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/forgot-password", forgotPasswordHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Hash the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", user.Username, user.Email, hashedPassword)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			// Duplicate entry error (unique constraint violation)
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}
		log.Fatal(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Registration successful for username: %s, email: %s", user.Username, user.Email)
}

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginForm LoginForm
	err := json.NewDecoder(r.Body).Decode(&loginForm)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	username := loginForm.Username
	password := loginForm.Password

	var storedPasswordHash string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPasswordHash)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set a session cookie upon successful login
	sessionCookie := http.Cookie{
		Name:     "session",
		Value:    username, // You can store user ID or other unique identifier here
		HttpOnly: true,     // Cookie cannot be accessed via JavaScript
	}
	http.SetCookie(w, &sessionCookie)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Login successful")
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var user struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	emailExists := true

	if !emailExists {
		http.Error(w, "Email not found", http.StatusNotFound)
		return
	}

	// Hash the new password before updating it in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Update the hashed password in the database for the given email
	_, err = db.Exec("UPDATE users SET password = ? WHERE email = ?", hashedPassword, user.Email)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Password reset successful.")
}

// logoutHandler - Clears session cookie upon logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie
	sessionCookie := http.Cookie{
		Name:     "session",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1, // Expire immediately
	}
	http.SetCookie(w, &sessionCookie)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Logout successful")
}

func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie("session")
		if err != nil || sessionCookie.Value == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check session validity, e.g., validate the session token against a session store

		// Call the next handler if the session is valid
		next.ServeHTTP(w, r)
	})
}

var shoes []Shoe

func GetShoes(w http.ResponseWriter, r *http.Request) {
	// Retrieve shoes from the database
	rows, err := db.Query("SELECT * FROM shoes")
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()

	shoes := []Shoe{} // Create a new slice to store the retrieved shoes

	for rows.Next() {
		var shoe Shoe
		err := rows.Scan(&shoe.ID, &shoe.Brand, &shoe.Model, &shoe.Size, &shoe.Color, &shoe.Price)
		if err != nil {
			panic(err.Error())
		}
		shoes = append(shoes, shoe)
	}

	if len(shoes) == 0 {
		// If no shoes are found, display a custom message
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No Shoes Available"))
		return
	}

	// Encode the shoes into JSON and send the response
	json.NewEncoder(w).Encode(shoes)
}

func GetShoe(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	shoeID := params["id"]

	var shoe Shoe
	err := db.QueryRow("SELECT * FROM shoes WHERE id = ?", shoeID).Scan(&shoe.ID, &shoe.Brand, &shoe.Model, &shoe.Size, &shoe.Color, &shoe.Price)
	if err != nil {
		// If no matching shoe is found, return a 404 Not Found response
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Shoe not found"))
		return
	}

	// If the shoe is found, return it in the response
	json.NewEncoder(w).Encode(shoe)
}

func CreateShoe(w http.ResponseWriter, r *http.Request) {
	var shoe Shoe
	err := json.NewDecoder(r.Body).Decode(&shoe)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert shoe data into the database
	_, err = db.Exec("INSERT INTO shoes (brand, model, size, color, price) VALUES (?, ?, ?, ?, ?)",
		shoe.Brand, shoe.Model, shoe.Size, shoe.Color, shoe.Price)
	if err != nil {
		// If insertion fails, return a custom error message
		w.WriteHeader(http.StatusInternalServerError) // Internal Server Error
		w.Write([]byte("Failed to add shoe"))
		return
	}

	// If insertion succeeds, return a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Shoe added successfully"))
}

func UpdateShoe(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var updatedShoe Shoe
	err := json.NewDecoder(r.Body).Decode(&updatedShoe)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Update shoe data in the database
	_, err = db.Exec("UPDATE shoes SET brand=?, model=?, size=?, color=?, price=? WHERE id=?",
		updatedShoe.Brand, updatedShoe.Model, updatedShoe.Size, updatedShoe.Color, updatedShoe.Price, params["id"])
	if err != nil {
		// If the update fails, return a custom error message
		w.WriteHeader(http.StatusInternalServerError) // Internal Server Error
		w.Write([]byte("Failed to update shoe"))
		return
	}

	// Update the local slice (optional)
	for index, shoe := range shoes {
		if shoe.ID == params["id"] {
			shoes[index] = updatedShoe
			break
		}
	}

	// If the update is successful, return a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("The information is updated successfully"))
}

func DeleteShoe(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	// Delete shoe data from the database
	_, err := db.Exec("DELETE FROM shoes WHERE id=?", params["id"])
	if err != nil {
		// If the delete operation fails, return a custom error message
		w.WriteHeader(http.StatusInternalServerError) // Internal Server Error
		w.Write([]byte("Failed to delete shoe"))
		return
	}

	// If the delete is successful, return a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Shoe deleted successfully"))
}

// Handler function to view the user's profile based on ID
func ViewProfile(w http.ResponseWriter, r *http.Request) {
	// Get the user ID from the request parameters
	params := mux.Vars(r)
	userID := params["id"]

	// Query the database to get the user's name and email based on the provided ID
	var user User
	err := db.QueryRow("SELECT username, email FROM users WHERE id = ?", userID).Scan(&user.Username, &user.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Encode the user profile into JSON and send the response
	json.NewEncoder(w).Encode(user)
}
