package main

import (
	"backend"
	"log"

	"github.com/gin-gonic/gin"

	prisma "db"
)

var client *prisma.PrismaClient

func main() {
	// Initialize Prisma Client
	client = prisma.NewClient()
	if err := client.Prisma.Connect(); err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Disconnect(); err != nil {
			log.Fatalf("Error disconnecting from the database: %v\n", err)
		}
	}()

	r := gin.Default()

	// Public routes
	handler := backend.Handler{DB: client}
	r.POST("/register", handler.Register)
	r.POST("/login", handler.Login)

	// Protected routes - requires JWT
	protected := r.Group("/api")
	protected.Use(backend.JWTAuthMiddleware())
	{
		protected.GET("/profile", handler.Profile)
	}

	r.Run(":8080")
}
