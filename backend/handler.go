package backend

import (
	prisma "db"
)

type Handler struct {
	DB *prisma.PrismaClient
}
