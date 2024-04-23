package main

import (
	"encoding/csv"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Secret key for JWT
const (
	jwtKey = "secret_key"
)

// In-memory database of users
var users = []User{
	{Username: "user", Password: "password", Role: "regular"},
	{Username: "admin", Password: "admin", Role: "admin"},
}

func main() {
	r := gin.Default()

	// Attach Routes
	r.POST("/login", loginHandler)

	r.GET("/home", authorize("regular"), homeHandler)

	r.POST("/addBook", authorize("admin"), validateAddBookData(), addBookHandler)

	r.POST("/deleteBook", authorize("admin"), validateDeleteBookData(), deleteBookHandler)

	r.Run(":8080")
}

// User represents the user.
type User struct {
	Username string
	Password string
	Role     string
}

// Book represents the structure of a book.
type Book struct {
	Name            string `json:"name"`
	Author          string `json:"author"`
	PublicationYear int    `json:"publication_year"`
}

// JWT claims struct.
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	for _, u := range users {
		if u.Username == user.Username && u.Password == user.Password {
			// Create token
			expirationTime := time.Now().Add(24 * time.Hour)
			claims := &Claims{
				Username: u.Username,
				Role:     u.Role,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(jwtKey))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"token": tokenString})
			return
		}
	}
	// User does not exist in inmemory DB.
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

func homeHandler(c *gin.Context) {
	fileNames := []string{"regularUser.csv"}
	if isAdmin(c) {
		fileNames = append(fileNames, "adminUser.csv")
	}

	books := make([]Book, 0)

	for _, fileName := range fileNames {
		file, err := os.Open(fileName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open CSV file"})
			return
		}
		defer file.Close()

		reader := csv.NewReader(file)

		// Read CSV records
		records, err := reader.ReadAll()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read CSV file"})
			return
		}

		// Parse CSV records into Book struct
		for _, record := range records[1:] {
			publicationYear, _ := strconv.Atoi(record[2])
			book := Book{
				Name:            record[0],
				Author:          record[1],
				PublicationYear: publicationYear,
			}
			books = append(books, book)
		}

		// Return JSON response
		c.JSON(http.StatusOK, books)
	}
}

func addBookHandler(c *gin.Context) {
	book := c.MustGet("book").(Book)

	file, err := os.OpenFile("regularUser.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "opening csv"})
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	err = writer.Write([]string{book.Name, book.Author, strconv.Itoa(book.PublicationYear)})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "writing books to csv"})
		return
	}

	c.JSON(http.StatusOK, book)
}

func deleteBookHandler(c *gin.Context) {
	book := c.MustGet("book").(Book)

	// Read the contents of the CSV file
	file, err := os.OpenFile("regularUser.csv", os.O_RDWR, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to open CSV file"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	lines, err := reader.ReadAll()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to read CSV file"})
		return
	}

	// Find the index of the book to delete (case-insensitive)
	var indexToDelete int = -1
	for i, line := range lines {
		if len(line) > 0 && strings.EqualFold(line[0], book.Name) {
			indexToDelete = i
			break
		}
	}

	if indexToDelete == -1 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Book not found"})
		return
	}

	// Remove the book from the slice
	lines = append(lines[:indexToDelete], lines[indexToDelete+1:]...)

	// Write the updated data back to the CSV file
	if err := file.Truncate(0); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to truncate CSV file"})
		return
	}

	if _, err := file.Seek(0, 0); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to seek CSV file"})
		return
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, line := range lines {
		if err := writer.Write(line); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to write to CSV file"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Book deleted successfully"})
}

// Function to validate book data
func validateBookData(book Book) error {
	// Validate publication year
	if book.PublicationYear <= 0 {
		return errors.New("publication year must be a positive integer")
	}

	if book.Author == "" {
		return errors.New("author should not be empty")
	}

	if book.Name == "" {
		return errors.New("name should not be empty")
	}

	return nil
}

// Middleware to authorize access.
func authorize(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Check if the token starts with "Bearer ", and remove it if it does
		const prefix = "Bearer "
		tokenString = strings.TrimPrefix(tokenString, prefix)

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			if claims.Role != "admin" && claims.Role != role {
				c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient privileges"})
				c.Abort()
				return
			}

			c.Set("user", User{
				Username: claims.Username,
				Role:     claims.Role,
			})
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	}
}

// Check if user is admin
func isAdmin(c *gin.Context) bool {
	user, _ := c.Get("user")
	if user != nil {
		if usr, ok := user.(User); ok {
			return usr.Role == "admin"
		}
	}
	return false
}

// Middleware to validate add book data
func validateAddBookData() gin.HandlerFunc {
	return func(c *gin.Context) {
		var book Book
		if err := c.ShouldBindJSON(&book); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
			c.Abort()
			return
		}

		if err := validateBookData(book); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			c.Abort()
			return
		}

		c.Set("book", book)
		c.Next()
	}
}

// Middleware to validate delete book data
func validateDeleteBookData() gin.HandlerFunc {
	return func(c *gin.Context) {
		var book Book
		if err := c.ShouldBindJSON(&book); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
			c.Abort()
			return
		}

		if book.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "name should not be empty"})
			c.Abort()
			return
		}

		c.Set("book", book)
		c.Next()
	}
}
