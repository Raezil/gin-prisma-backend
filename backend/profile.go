package backend

import (
	"context"
	prisma "db"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (handler *Handler) Profile(c *gin.Context) {
	userId, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No user ID in context"})
		return
	}

	user, err := handler.DB.User.FindUnique(
		prisma.User.ID.Equals(userId.(string)),
	).Exec(context.Background())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":    user.ID,
		"email": user.Email,
	})
}
