package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

// Test case: No Authorization header provided.
func TestJWTAuthMiddleware_NoAuthHeader(t *testing.T) {
	// Create a new Gin router and apply the JWTAuthMiddleware.
	router := gin.New()
	router.Use(JWTAuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		// This handler should not be reached if the middleware works.
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a new request without an Authorization header.
	req, _ := http.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	// Expect an Unauthorized status.
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d but got %d", http.StatusUnauthorized, recorder.Code)
	}

	// Optionally, check the error message in the response body.
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Errorf("Error parsing response: %v", err)
	}
	if response["error"] != "Missing Authorization header" {
		t.Errorf("Unexpected error message: %s", response["error"])
	}
}

// Test case: Invalid token provided in the Authorization header.
func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	router := gin.New()
	router.Use(JWTAuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a request with an invalid token.
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d but got %d", http.StatusUnauthorized, recorder.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Errorf("Error parsing response: %v", err)
	}
	if response["error"] != "Invalid token" {
		t.Errorf("Unexpected error message: %s", response["error"])
	}
}

// Test case: Valid token is provided.
func TestJWTAuthMiddleware_ValidToken(t *testing.T) {
	router := gin.New()
	router.Use(JWTAuthMiddleware())
	// Create a test handler that returns the userId from the context.
	router.GET("/test", func(c *gin.Context) {
		userId, exists := c.Get("userId")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "userId not set"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"userId": userId})
	})

	// Create a valid JWT token with a "sub" (subject) claim.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "12345",
	})
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		t.Fatalf("Error signing token: %v", err)
	}

	// Create a request with the valid token.
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	// Expect an OK status.
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d but got %d", http.StatusOK, recorder.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Errorf("Error parsing response: %v", err)
	}
	if response["userId"] != "12345" {
		t.Errorf("Expected userId '12345' but got '%s'", response["userId"])
	}
}
