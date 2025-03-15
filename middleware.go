package nanite

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// ### Validation Middleware

func ValidationMiddleware(chains ...*ValidationChain) MiddlewareFunc {
	return func(ctx *Context, next func()) {
		if ctx.IsAborted() {
			return
		}

		// Handle request data parsing for POST, PUT, PATCH, DELETE methods
		if len(chains) > 0 && (ctx.Request.Method == "POST" || ctx.Request.Method == "PUT" ||
			ctx.Request.Method == "PATCH" || ctx.Request.Method == "DELETE") {

			contentType := ctx.Request.Header.Get("Content-Type")

			// Parse form data (application/x-www-form-urlencoded or multipart/form-data)
			if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
				strings.HasPrefix(contentType, "multipart/form-data") {
				if err := ctx.Request.ParseForm(); err != nil {
					ve := getValidationError("", "failed to parse form data")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				// Store form data in ctx.Values
				formData := make(map[string]interface{})
				for key, values := range ctx.Request.Form {
					if len(values) == 1 {
						formData[key] = values[0]
					} else {
						formData[key] = values
					}
				}
				ctx.Values["formData"] = formData
			}

			// Parse JSON body (application/json)
			if strings.HasPrefix(contentType, "application/json") {
				buffer := bufferPool.Get().(*bytes.Buffer)
				buffer.Reset()
				defer bufferPool.Put(buffer)

				if _, err := io.Copy(buffer, ctx.Request.Body); err != nil {
					ve := getValidationError("", "failed to read request body")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				bodyBytes := buffer.Bytes()
				// Restore request body for downstream use
				ctx.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				var body map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					ve := getValidationError("", "invalid JSON")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				ctx.Values["body"] = body
			}
		}

		// Attach validation rules to LazyFields
		for _, chain := range chains {
			field := ctx.Field(chain.field)                   // Get or create the LazyField
			field.rules = append(field.rules, chain.rules...) // Append validation rules
		}

		// Proceed to the next middleware or handler
		next()
	}
}

// ExecuteMiddleware executes the middleware chain for a route
func executeMiddlewareChain(c *Context, handler HandlerFunc, middleware []MiddlewareFunc) {
	// No middleware, just execute the handler
	if len(middleware) == 0 {
		handler(c)
		return
	}

	// Build the middleware chain
	var next func()
	var index int

	next = func() {
		if index < len(middleware) {
			currentMiddleware := middleware[index]
			index++
			currentMiddleware(c, next)
		} else {
			// End of middleware chain, execute the handler
			handler(c)
		}
	}

	// Start the middleware chain
	index = 0
	next()
}
