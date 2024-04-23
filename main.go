package main

import (
	"encoding/csv"
	"net/http"
	"os"
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

	// Route to handle CSV file reading and output
	r.GET("/home", authorize("regular"), homeHandler)

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
	PublicationYear string `json:"publication_year"`
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
			book := Book{
				Name:            record[0],
				Author:          record[1],
				PublicationYear: record[2],
			}
			books = append(books, book)
		}

		// Return JSON response
		c.JSON(http.StatusOK, books)
	}
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
