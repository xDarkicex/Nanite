package nanite

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

// Object pool for ValidationError
var validationErrorPool = sync.Pool{
	New: func() interface{} {
		return &ValidationError{}
	},
}

func getValidationError(field, error string) *ValidationError {
	ve := validationErrorPool.Get().(*ValidationError)
	ve.Field = field
	ve.Err = error
	return ve
}

func putValidationError(ve *ValidationError) {
	ve.Field = ""
	ve.Err = ""
	validationErrorPool.Put(ve)
}

// ValidatorFunc defines the signature for validation functions.
// It validates a string value and returns an error if invalid.
type ValidatorFunc func(string) error

// ValidationChain represents a chain of validation rules for a field.
type ValidationChain struct {
	field string
	rules []ValidatorFunc
}

// ### Validation Support

// IsObject adds a rule that the field must be a JSON object.
func (vc *ValidationChain) IsObject() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		if !strings.HasPrefix(value, "{") || !strings.HasSuffix(value, "}") {
			return getValidationError(vc.field, "must be an object")
		}
		return nil
	})
	return vc
}

// IsArray adds a rule that the field must be a JSON array.
func (vc *ValidationChain) IsArray() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return getValidationError(vc.field, "must be an array")
		}
		return nil
	})
	return vc
}

// Custom adds a custom validation function to the chain.
func (vc *ValidationChain) Custom(fn func(string) error) *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		if err := fn(value); err != nil {
			return getValidationError(vc.field, err.Error())
		}
		return nil
	})
	return vc
}

// OneOf adds a rule that the field must be one of the specified options.
func (vc *ValidationChain) OneOf(options ...string) *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		for _, option := range options {
			if value == option {
				return nil
			}
		}
		return getValidationError(vc.field, fmt.Sprintf("must be one of: %s", strings.Join(options, ", ")))
	})
	return vc
}

// Matches adds a rule that the field must match the specified regular expression.
func (vc *ValidationChain) Matches(pattern string) *ValidationChain {
	re, err := regexp.Compile(pattern)
	if err != nil {
		vc.rules = append(vc.rules, func(value string) error {
			return getValidationError(vc.field, "invalid validation pattern")
		})
		return vc
	}

	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		if !re.MatchString(value) {
			return getValidationError(vc.field, "invalid format")
		}
		return nil
	})
	return vc
}

// Length adds a rule that the field must have a length within the specified range.
func (vc *ValidationChain) Length(min, max int) *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		length := len(value)
		if length < min {
			return getValidationError(vc.field, fmt.Sprintf("must be at least %d characters", min))
		}
		if length > max {
			return getValidationError(vc.field, fmt.Sprintf("must be at most %d characters", max))
		}
		return nil
	})
	return vc
}

// Max adds a rule that the field must be at most a specified integer value.
func (vc *ValidationChain) Max(max int) *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		num, err := strconv.Atoi(value)
		if err != nil {
			return getValidationError(vc.field, "must be a number")
		}
		if num > max {
			return getValidationError(vc.field, fmt.Sprintf("must be at most %d", max))
		}
		return nil
	})
	return vc
}

// Min adds a rule that the field must be at least a specified integer value.
func (vc *ValidationChain) Min(min int) *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		num, err := strconv.Atoi(value)
		if err != nil {
			return getValidationError(vc.field, "must be a number")
		}
		if num < min {
			return getValidationError(vc.field, fmt.Sprintf("must be at least %d", min))
		}
		return nil
	})
	return vc
}

// IsBoolean adds a rule that the field must be a boolean value.
func (vc *ValidationChain) IsBoolean() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		lowerVal := strings.ToLower(value)
		if lowerVal != "true" && lowerVal != "false" && lowerVal != "1" && lowerVal != "0" {
			return getValidationError(vc.field, "must be a boolean value")
		}
		return nil
	})
	return vc
}

// IsFloat adds a rule that the field must be a floating-point number.
func (vc *ValidationChain) IsFloat() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return getValidationError(vc.field, "must be a number")
		}
		return nil
	})
	return vc
}

// IsInt adds a rule that the field must be an integer.
func (vc *ValidationChain) IsInt() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil
		}
		if _, err := strconv.Atoi(value); err != nil {
			return getValidationError(vc.field, "must be an integer")
		}
		return nil
	})
	return vc
}

// IsEmail adds a rule that the field must be a valid email address.
func (vc *ValidationChain) IsEmail() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return nil // Skip if empty unless required
		}
		if !strings.Contains(value, "@") || !strings.Contains(value, ".") {
			return getValidationError(vc.field, "invalid email format")
		}
		return nil
	})
	return vc
}

// Required adds a rule that the field must not be empty.
func (vc *ValidationChain) Required() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return getValidationError(vc.field, "field is required")
		}
		return nil
	})
	return vc
}

// NewValidationChain creates a new ValidationChain for the specified field.
func NewValidationChain(field string) *ValidationChain {
	return &ValidationChain{
		field: field,
		rules: make([]ValidatorFunc, 0, 5), // Pre-allocate for efficiency
	}
}
