package main

import (
	"github.com/peter-matc/ring_signature/models"
	"github.com/peter-matc/ring_signature/router"
)

func main() {
	// ring.SignWrapper()
	models.InitRSAData()
	router.Start()
}
