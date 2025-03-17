package nanite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	errRequired      = "field is required"
	errInvalidFormat = "invalid format"
	errMustBeNumber  = "must be a number"
	errMustBeBoolean = "must be a boolean value"
)

// ValidationError represents a single validation error with field and message.
type ValidationError struct {
	Field string `json:"field"` // Field name that failed validation
	Err   string `json:"error"` // Error message describing the failure
}

// Error implements the error interface.
func (ve *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.Field, ve.Err)
}

// ValidatorFunc defines the signature for validation functions.
// It validates a string value and returns a pre-allocated ValidationError object.
type ValidatorFunc func(string) *ValidationError

// ValidationChain represents a chain of validation rules for a field.
type ValidationChain struct {
	field              string
	rules              []ValidatorFunc
	preAllocatedErrors []*ValidationError
}

// ### Validation Support

// IsObject adds a rule that the field must be a JSON object.
//
//go:inline
func (vc *ValidationChain) IsObject() *ValidationChain {
	// Pre-allocate the error
	errObj := getValidationError(vc.field, "must be an object")
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if !strings.HasPrefix(value, "{") || !strings.HasSuffix(value, "}") {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// IsArray adds a rule that the field must be a JSON array.
func (vc *ValidationChain) IsArray() *ValidationChain {
	// Pre-allocate the error
	errObj := getValidationError(vc.field, "must be an array")
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// Custom adds a custom validation function to the chain.
func (vc *ValidationChain) Custom(fn func(string) error) *ValidationChain {
	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if err := fn(value); err != nil {
			// This is the one case where we have to create an error at runtime
			// since we can't know the error message in advance
			return getValidationError(vc.field, err.Error())
		}
		return nil
	})
	return vc
}

// OneOf adds a rule that the field must be one of the specified options.
func (vc *ValidationChain) OneOf(options ...string) *ValidationChain {
	// Pre-allocate the error - format the message at setup time
	message := fmt.Sprintf("must be one of: %s", strings.Join(options, ", "))
	errObj := getValidationError(vc.field, message)
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		for _, option := range options {
			if value == option {
				return nil
			}
		}
		return vc.preAllocatedErrors[errIndex]
	})
	return vc
}

// Matches adds a rule that the field must match the specified regular expression.
func (vc *ValidationChain) Matches(pattern string) *ValidationChain {
	// Pre-compile the regex at setup time instead of per-request
	re, err := regexp.Compile(pattern)

	// Handle invalid pattern at setup time
	if err != nil {
		invalidPatternErr := getValidationError(vc.field, "invalid validation pattern")
		vc.preAllocatedErrors = append(vc.preAllocatedErrors, invalidPatternErr)
		errIndex := len(vc.preAllocatedErrors) - 1

		vc.rules = append(vc.rules, func(value string) *ValidationError {
			return vc.preAllocatedErrors[errIndex]
		})
		return vc
	}

	// Pre-allocate for invalid format error
	formatErr := getValidationError(vc.field, errInvalidFormat)
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, formatErr)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if !re.MatchString(value) {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// Length adds a rule that the field must have a length within specified range
func (vc *ValidationChain) Length(min, maxLength int) *ValidationChain {
	// Pre-allocate error messages
	tooShortErr := getValidationError(vc.field, fmt.Sprintf("must be at least %d characters", min))
	tooLongErr := getValidationError(vc.field, fmt.Sprintf("must be at most %d characters", maxLength))
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, tooShortErr, tooLongErr)

	// Store indices
	tooShortIndex := len(vc.preAllocatedErrors) - 2
	tooLongIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		length := len(value)
		if length < min {
			return vc.preAllocatedErrors[tooShortIndex]
		}

		if length > maxLength {
			return vc.preAllocatedErrors[tooLongIndex]
		}

		return nil
	})
	return vc
}

// Max adds a rule that the field must be at most a specified integer value.
func (vc *ValidationChain) Max(max int) *ValidationChain {
	// Pre-allocate errors
	numErr := getValidationError(vc.field, errMustBeNumber)
	maxErr := getValidationError(vc.field, fmt.Sprintf("must be at most %d", max))
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, numErr, maxErr)

	numErrIndex := len(vc.preAllocatedErrors) - 2
	maxErrIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		num, err := strconv.Atoi(value)
		if err != nil {
			return vc.preAllocatedErrors[numErrIndex]
		}

		if num > max {
			return vc.preAllocatedErrors[maxErrIndex]
		}
		return nil
	})
	return vc
}

// Min adds a rule that the field must be at least a specified integer value.
func (vc *ValidationChain) Min(min int) *ValidationChain {
	// Pre-allocate errors
	numErr := getValidationError(vc.field, errMustBeNumber)
	minErr := getValidationError(vc.field, fmt.Sprintf("must be at least %d", min))
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, numErr, minErr)

	numErrIndex := len(vc.preAllocatedErrors) - 2
	minErrIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		num, err := strconv.Atoi(value)
		if err != nil {
			return vc.preAllocatedErrors[numErrIndex]
		}

		if num < min {
			return vc.preAllocatedErrors[minErrIndex]
		}
		return nil
	})
	return vc
}

// IsBoolean adds a rule that the field must be a boolean value.
func (vc *ValidationChain) IsBoolean() *ValidationChain {
	// Pre-allocate the error
	errObj := getValidationError(vc.field, errMustBeBoolean)
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		lowerVal := strings.ToLower(value)
		if lowerVal != "true" && lowerVal != "false" && lowerVal != "1" && lowerVal != "0" {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// IsFloat adds a rule that the field must be a floating-point number.
//
//go:inline
func (vc *ValidationChain) IsFloat() *ValidationChain {
	// Pre-allocate the error
	errObj := getValidationError(vc.field, errMustBeNumber)
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// IsInt adds a rule that the field must be an integer.
//
//go:inline
func (vc *ValidationChain) IsInt() *ValidationChain {
	// Pre-allocate the error
	errObj := getValidationError(vc.field, "must be an integer")
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if _, err := strconv.Atoi(value); err != nil {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// IsEmail adds a rule that the field must be a valid email address.
//
//go:inline
func (vc *ValidationChain) IsEmail() *ValidationChain {
	// Pre-allocate the error
	errObj := getValidationError(vc.field, "invalid email format")
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	errIndex := len(vc.preAllocatedErrors) - 1

	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			return nil
		}

		if !strings.Contains(value, "@") || !strings.Contains(value, ".") {
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// Required adds a rule that the field must not be empty.
//
//go:inline
func (vc *ValidationChain) Required() *ValidationChain {
	errObj := getValidationError(vc.field, errRequired)
	vc.preAllocatedErrors = append(vc.preAllocatedErrors, errObj)
	// Store index for this specific error
	errIndex := len(vc.preAllocatedErrors) - 1
	vc.rules = append(vc.rules, func(value string) *ValidationError {
		if value == "" {
			// Return the pre-allocated error directly
			return vc.preAllocatedErrors[errIndex]
		}
		return nil
	})
	return vc
}

// NewValidationChain creates a new ValidationChain for the specified field.
func NewValidationChain(field string) *ValidationChain {
	return getValidationChain(field)
}

// Release returns the ValidationChain to the pool
func (vc *ValidationChain) Release() {
	// Return all pre-allocated errors to the pool
	for _, err := range vc.preAllocatedErrors {
		putValidationError(err)
	}

	vc.preAllocatedErrors = vc.preAllocatedErrors[:0]
	vc.rules = vc.rules[:0]
	putValidationChain(vc)
}

// JSONParsingConfig provides configuration options for the JSONParsingMiddleware
type JSONParsingConfig struct {
	MaxSize        int64                 // Maximum allowed size for JSON request bodies
	ErrorHandler   func(*Context, error) // Custom error handler for parsing errors
	TargetKey      string                // Context key where parsed JSON is stored (default: "body")
	RequireJSON    bool                  // Require all requests to have application/json content type
	AllowEmptyBody bool                  // Allow empty request bodies (results in empty object)
}

// DefaultJSONConfig returns a default configuration for JSON parsing middleware
func DefaultJSONConfig() JSONParsingConfig {
	return JSONParsingConfig{
		MaxSize:        10 << 20, // 10MB
		TargetKey:      "body",
		RequireJSON:    false,
		AllowEmptyBody: true,
	}
}

// JSONParsingMiddleware creates middleware that parses JSON request bodies.
// It uses an optimized io.TeeReader approach to parse the body without
// consuming it, making it available for downstream handlers.
//
// Parameters:
//   - config: Optional configuration for the middleware. If nil, defaults are used.
//
// Returns:
//   - MiddlewareFunc: Middleware function that can be registered with the router
func JSONParsingMiddleware(config *JSONParsingConfig) MiddlewareFunc {
	// Use default config if none provided
	cfg := DefaultJSONConfig()
	if config != nil {
		cfg = *config
	}

	return func(ctx *Context, next func()) {
		if ctx.IsAborted() {
			return
		}

		// Check if we need to process this request
		contentType := ctx.Request.Header.Get("Content-Type")
		isJSON := strings.HasPrefix(contentType, "application/json")

		if !isJSON {
			if cfg.RequireJSON {
				// If JSON is required but content-type is not JSON, abort
				if cfg.ErrorHandler != nil {
					cfg.ErrorHandler(ctx, fmt.Errorf("content type must be application/json"))
				} else {
					ctx.JSON(http.StatusUnsupportedMediaType, map[string]interface{}{
						"error": "content type must be application/json",
					})
				}
				return
			}
			// If JSON is not required and content-type is not JSON, skip parsing
			next()
			return
		}

		// Check Content-Length if available for early rejection
		if ctx.Request.ContentLength > cfg.MaxSize && ctx.Request.ContentLength != -1 {
			if cfg.ErrorHandler != nil {
				cfg.ErrorHandler(ctx, fmt.Errorf("request body too large"))
			} else {
				ctx.JSON(http.StatusRequestEntityTooLarge, map[string]interface{}{
					"error": "request body too large",
				})
			}
			return
		}

		// Get buffer from pool
		buffer := bufferPool.Get().(*bytes.Buffer)
		buffer.Reset()
		defer bufferPool.Put(buffer)

		// Handle empty bodies
		if ctx.Request.ContentLength == 0 {
			if cfg.AllowEmptyBody {
				// Use an empty object for empty bodies
				ctx.Values[cfg.TargetKey] = make(map[string]interface{})
				next()
				return
			} else {
				if cfg.ErrorHandler != nil {
					cfg.ErrorHandler(ctx, fmt.Errorf("empty request body not allowed"))
				} else {
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{
						"error": "empty request body not allowed",
					})
				}
				return
			}
		}

		// Create a limited reader to prevent DoS from excessively large bodies
		limitedBody := io.LimitReader(ctx.Request.Body, cfg.MaxSize)

		// Use TeeReader to simultaneously read the body once while writing to buffer
		teeBody := io.TeeReader(limitedBody, buffer)

		// Parse the JSON directly from the tee reader
		var body map[string]interface{}
		if err := json.NewDecoder(teeBody).Decode(&body); err != nil {
			if cfg.ErrorHandler != nil {
				cfg.ErrorHandler(ctx, err)
			} else {
				ctx.JSON(http.StatusBadRequest, map[string]interface{}{
					"error": "invalid JSON: " + err.Error(),
				})
			}
			return
		}

		// Close original body and replace with buffered copy for downstream handlers
		ctx.Request.Body.Close()
		ctx.Request.Body = io.NopCloser(bytes.NewReader(buffer.Bytes()))

		// Store parsed body in context with the configured key
		ctx.Values[cfg.TargetKey] = body

		// Proceed to the next middleware or handler
		next()
	}
}
