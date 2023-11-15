package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	// "github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	// "github.com/gin-contrib/cors"
	// "github.com/gin-gonic/gin"
	"github.com/rs/cors"
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

	// CORS middleware
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"https://teal-malasada-553c48.netlify.app",
			"https://jhonrheybelcina.github.io",
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"},
		AllowCredentials: true,
	})

	// Apply CORS middleware to all routes
	handler := corsHandler.Handler(r)

	// Handle protected routes with authenticationMiddleware
	protectedRoutes := r.PathPrefix("/protected").Subrouter()
	protectedRoutes.Use(authenticationMiddleware)

	// Protected routes
	// protectedRoutes.HandleFunc("/showAll", GetShoes).Methods("GET")
	// protectedRoutes.HandleFunc("/show/{id}", GetShoe).Methods("GET")
	// protectedRoutes.HandleFunc("/create", CreateShoe).Methods("POST")
	// protectedRoutes.HandleFunc("/update/{id}", UpdateShoe).Methods("PUT")
	// protectedRoutes.HandleFunc("/delete/{id}", DeleteShoe).Methods("DELETE")
	// protectedRoutes.HandleFunc("/profile/{id}", ViewProfile).Methods("GET")

	//Public routes
	r.HandleFunc("/update/{id}", UpdateShoe).Methods("PUT")
	r.HandleFunc("/delete/{id}", DeleteShoe).Methods("DELETE")
	r.HandleFunc("/create", CreateShoe).Methods("POST")
	r.HandleFunc("/showAll", GetShoes).Methods("GET")
	r.HandleFunc("/show/{id}", GetShoe).Methods("GET")
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/forgot-password", forgotPasswordHandler).Methods("POST")
	r.HandleFunc("/check-email", CheckEmailHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/profile/{id}", ViewProfile).Methods("GET")

	// Use the CORS-wrapped handler
	http.Handle("/", handler)
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
	Email    string `json:"email"`
	Password string `json:"password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginForm LoginForm
	err := json.NewDecoder(r.Body).Decode(&loginForm)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	email := loginForm.Email
	password := loginForm.Password

	var storedPasswordHash string
	var username string
	var userID int // Assuming UserID is of type int in the database

	// Fetch username, password hash, and UserID from the database based on the email
	err = db.QueryRow("SELECT id, username, password FROM users WHERE email = ?", email).Scan(&userID, &username, &storedPasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set a session cookie upon successful login (this example uses the email as the session value)
	sessionCookie := http.Cookie{
		Name:     "session",
		Value:    strconv.Itoa(userID), // Store the user ID in the session cookie
		HttpOnly: true,                 // Cookie cannot be accessed via JavaScript
	}
	http.SetCookie(w, &sessionCookie)

	// Prepare the response including the UserID, Username, and message
	response := struct {
		UserID   int    `json:"userId"`
		Username string `json:"username"`
		Message  string `json:"message"`
	}{
		UserID:   userID,
		Username: username,
		Message:  "Login successful",
	}

	// Send the JSON response including UserID, Username, and message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}


// func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
// 	var user struct {
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 	}
// 	err := json.NewDecoder(r.Body).Decode(&user)
// 	if err != nil {
// 		http.Error(w, "Invalid JSON", http.StatusBadRequest)
// 		return
// 	}

// 	emailExists := true

// 	if !emailExists {
// 		http.Error(w, "Email not found", http.StatusNotFound)
// 		return
// 	}

// 	// Hash the new password before updating it in the database
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
// 		return
// 	}

// 	// Update the hashed password in the database for the given email
// 	_, err = db.Exec("UPDATE users SET password = ? WHERE email = ?", hashedPassword, user.Email)
// 	if err != nil {
// 		http.Error(w, "Failed to update password", http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	fmt.Fprint(w, "Password reset successful.")
// }

// CheckEmailHandler handles the request to check if the email exists.
func CheckEmailHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if the email exists in the database
	if !emailExists(user.Email) {
		http.Error(w, "Email not found", http.StatusNotFound)
		return
	}

	// Respond with a JSON indicating that the email exists
	response := map[string]bool{"emailExists": true}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func emailExists(email string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		log.Println("Error checking email existence:", err)
		return false
	}
	return count > 0
}

// ForgotPasswordHandler handles the request to reset the user's password.
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if the email exists in the database (replace this with your actual database query)
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

	// Update the hashed password in the database for the given email (replace this with your actual database update query)
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
	// Query all shoes from the database
	rows, err := db.Query("SELECT * FROM shoes")
	if err != nil {
		// Handle the error
		log.Println("Error getting shoes from database:", err)
		http.Error(w, "Failed to retrieve shoes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the shoes
	var shoes []Shoe

	// Iterate over the rows and populate the shoes slice
	for rows.Next() {
		var shoe Shoe
		if err := rows.Scan(&shoe.ID, &shoe.Brand, &shoe.Model, &shoe.Size, &shoe.Color, &shoe.Price); err != nil {
			// Handle the error
			log.Println("Error scanning shoe from row:", err)
			http.Error(w, "Failed to retrieve shoes", http.StatusInternalServerError)
			return
		}
		shoes = append(shoes, shoe)
	}

	// Check for errors from iterating over rows
	if err := rows.Err(); err != nil {
		log.Println("Error iterating over rows:", err)
		http.Error(w, "Failed to retrieve shoes", http.StatusInternalServerError)
		return
	}

	// Encode the shoes slice into JSON and send the response
	json.NewEncoder(w).Encode(shoes)
}

func GetShoe(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	shoeID := params["id"]

	// Convert shoeID to integer
	shoeIDInt, err := strconv.Atoi(shoeID)
	if err != nil {
		// Handle the error, e.g., return a bad request response
		http.Error(w, "Invalid shoe ID", http.StatusBadRequest)
		return
	}

	var shoe Shoe
	err = db.QueryRow("SELECT * FROM shoes WHERE id = ?", shoeIDInt).Scan(&shoe.ID, &shoe.Brand, &shoe.Model, &shoe.Size, &shoe.Color, &shoe.Price)
	if err != nil {
		// Log the error for debugging
		log.Println("Error getting shoe from database:", err)
		// If no matching shoe is found, return a 404 Not Found response
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Shoe not found"))
		return
	}

	// If the shoe is found, return it in the response
	json.NewEncoder(w).Encode(shoe)
}

func CreateShoe(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Create an empty shoe instance to decode the JSON or form data into
	var newShoe Shoe

	// Try to unmarshal the request body as JSON
	if err := json.Unmarshal(body, &newShoe); err != nil {
		// If it's not JSON, try to parse it as form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Parse form fields
		brand := r.FormValue("brand")
		model := r.FormValue("model")
		size, _ := strconv.Atoi(r.FormValue("size"))
		color := r.FormValue("color")
		price, _ := strconv.ParseFloat(r.FormValue("price"), 64)

		// Set values in the shoe instance
		newShoe = Shoe{
			Brand: brand,
			Model: model,
			Size:  size,
			Color: color,
			Price: price,
		}
	}

	// Optional: Perform validation on the form fields or the newShoe instance

	// Insert shoe data into the database
	_, err = db.Exec("INSERT INTO shoes (brand, model, size, color, price) VALUES (?, ?, ?, ?, ?)",
		newShoe.Brand, newShoe.Model, newShoe.Size, newShoe.Color, newShoe.Price)
	if err != nil {
		// Handle the error
		log.Println("Error inserting into database:", err)
		http.Error(w, "Failed to add shoe", http.StatusInternalServerError)
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

	// Fetch the existing shoe data from the database
	var existingShoe Shoe
	err = db.QueryRow("SELECT * FROM shoes WHERE id = ?", params["id"]).Scan(&existingShoe.ID, &existingShoe.Brand, &existingShoe.Model, &existingShoe.Size, &existingShoe.Color, &existingShoe.Price)
	if err != nil {
		// Handle the error, e.g., return a 404 Not Found response
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Shoe not found"))
		return
	}

	// Update only the fields that are provided in the request
	if updatedShoe.Brand != "" {
		existingShoe.Brand = updatedShoe.Brand
	}
	if updatedShoe.Model != "" {
		existingShoe.Model = updatedShoe.Model
	}
	if updatedShoe.Size != 0 {
		existingShoe.Size = updatedShoe.Size
	}
	if updatedShoe.Color != "" {
		existingShoe.Color = updatedShoe.Color
	}
	if updatedShoe.Price != 0 {
		existingShoe.Price = updatedShoe.Price
	}

	// Update shoe data in the database
	_, err = db.Exec("UPDATE shoes SET brand=?, model=?, size=?, color=?, price=? WHERE id=?",
		existingShoe.Brand, existingShoe.Model, existingShoe.Size, existingShoe.Color, existingShoe.Price, params["id"])
	if err != nil {
		// If the update fails, return a custom error message
		w.WriteHeader(http.StatusInternalServerError) // Internal Server Error
		w.Write([]byte("Failed to update shoe"))
		return
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
