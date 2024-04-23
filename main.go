package main

import (
	"net/http"
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

	r.Run(":8080")
}

// User represents the user.
type User struct {
	Username string
	Password string
	Role     string
}

// JWT claims struct
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

// Middleware to authorize access.
func authorize(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, _ := c.Get("user")
		if user != nil {
			if usr, ok := user.(User); ok {
				if usr.Role != role && usr.Role != "admin" {
					c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient privileges"})
					c.Abort()
					return
				}
			}
		}
		c.Next()
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
