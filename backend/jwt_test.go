package backend

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func TestGenerateJWT(t *testing.T) {
	userId := "test-user"

	// Generate the JWT token
	tokenString, err := generateJWT(userId)
	if err != nil {
		t.Fatalf("Error generating JWT: %v", err)
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})
	if err != nil {
		t.Fatalf("Error parsing JWT: %v", err)
	}

	// Extract and verify the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		t.Fatalf("Token is invalid or claims are not of type MapClaims")
	}

	// Check that the "sub" claim matches the expected userId
	if claims["sub"] != userId {
		t.Errorf("expected 'sub' claim to be %q, got %q", userId, claims["sub"])
	}

	// Verify the expiration time is roughly 72 hours from now.
	expFloat, ok := claims["exp"].(float64)
	if !ok {
		t.Error("exp claim is not a number")
	}
	expTime := time.Unix(int64(expFloat), 0)
	expectedDuration := time.Hour * 72
	// Allow a tolerance of a few seconds
	tolerance := time.Second * 5
	actualDuration := time.Until(expTime)
	if actualDuration < expectedDuration-tolerance || actualDuration > expectedDuration+tolerance {
		t.Errorf("unexpected token expiration time: got %v, expected approximately %v", actualDuration, expectedDuration)
	}
}
