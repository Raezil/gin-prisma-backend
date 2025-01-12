package backend

import (
	"time"

	"github.com/golang-jwt/jwt"
)

func generateJWT(userId string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userId,
		"exp": time.Now().Add(time.Hour * 72).Unix(), // Token expires in 72 hours
		"iat": time.Now().Unix(),
	})

	// Sign and get the complete encoded token as a string
	return token.SignedString(jwtSecretKey)
}
