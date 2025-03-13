// package main

// import (
// 	"fmt"
// 	"net/http"
// 	"time"

// 	"github.com/google/uuid"
// 	nanite "github.com/xDarkicex/Nanite"
// )

// func main() {
// 	router := nanite.New()

// 	// Register middleware
// 	router.Use(nanite.LoggingMiddleware())

// 	// Example with Enhanced Validation for User Creation
// 	router.Post("/users", createUser, nanite.ValidationMiddleware(
// 		nanite.NewValidationChain("email").Required().IsEmail(),
// 		nanite.NewValidationChain("age").IsInt().Min(18).Max(120),
// 		nanite.NewValidationChain("name").Required().Length(2, 50),
// 		nanite.NewValidationChain("role").OneOf("admin", "user", "editor"),
// 		nanite.NewValidationChain("settings").IsObject(),
// 		nanite.NewValidationChain("tags").IsArray(),
// 	))

// 	// Example with Enhanced Validation for Product Creation
// 	router.Post("/products", createProduct, nanite.ValidationMiddleware(
// 		nanite.NewValidationChain("name").Required().Length(3, 100),
// 		nanite.NewValidationChain("price").Required().IsFloat().Min(0),
// 		nanite.NewValidationChain("inStock").IsBoolean(),
// 		nanite.NewValidationChain("category").Required().Matches(`^[a-zA-Z0-9-_]+$`),
// 		nanite.NewValidationChain("description").Length(10, 1000),
// 	))

// 	// Example with Form Data Validation
// 	router.Post("/contact", handleContact, nanite.ValidationMiddleware(
// 		nanite.NewValidationChain("subject").Required().Length(5, 100),
// 		nanite.NewValidationChain("message").Required().Length(10, 2000),
// 		nanite.NewValidationChain("email").Required().IsEmail(),
// 		nanite.NewValidationChain("priority").OneOf("low", "medium", "high"),
// 	))

// 	// Start the server
// 	router.Start("8080")
// }

// func createUser(c *nanite.Context) {
// 	// Check validation errors
// 	if !c.CheckValidation() {
// 		return // Response already sent with error details
// 	}

// 	// Get validated data from context
// 	body := c.Values["body"].(map[string]interface{})

// 	// Process the validated data
// 	user := map[string]interface{}{
// 		"id":      uuid.New().String(),
// 		"email":   body["email"],
// 		"name":    body["name"],
// 		"age":     body["age"],
// 		"role":    body["role"],
// 		"created": time.Now().Format(time.RFC3339),
// 	}

// 	// Return response
// 	c.JSON(http.StatusCreated, user)
// }

// func createProduct(c *nanite.Context) {
// 	if !c.CheckValidation() {
// 		return
// 	}

// 	// Processing...
// 	c.JSON(http.StatusCreated, map[string]interface{}{
// 		"status": "product created",
// 	})
// }

// func handleContact(c *nanite.Context) {
// 	if !c.CheckValidation() {
// 		return
// 	}

// 	// Access form data
// 	formData := c.Values["formData"].(map[string]interface{})

// 	// Process contact form...
// 	c.String(http.StatusOK, fmt.Sprintf("Thank you for your %s priority message", formData["priority"]))
// }
