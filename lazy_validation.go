// lazy_validation.go
package nanite

import (
	"fmt"
	"slices"
)

// LazyField represents a field that will be validated lazily
type LazyField struct {
	name      string          // The field's name (e.g., "username")
	getValue  func() string   // Function to fetch the raw value from the request
	rules     []ValidatorFunc // List of validation rules (e.g., regex checks)
	validated bool            // Tracks if validation has run
	value     string          // Stores the validated value
	err       error           // Stores any validation error
}

// Value validates and returns the field value
func (lf *LazyField) Value() (string, error) {
	if !lf.validated {
		rawValue := lf.getValue()
		lf.value = rawValue

		for _, rule := range lf.rules {
			if err := rule(rawValue); err != nil {
				// Store the error directly - no need to create a copy
				// since we're storing it in lf.err for the lifetime of the LazyField
				lf.err = err
				break
			}
		}

		lf.validated = true
	}

	return lf.value, lf.err
}

// Field gets or creates a LazyField for the specified field name
func (c *Context) Field(name string) *LazyField {
	// Safety net: initialize lazyFields if nil
	if c.lazyFields == nil {
		c.lazyFields = make(map[string]*LazyField)
	}

	field, exists := c.lazyFields[name]
	if !exists {
		// Use the pool instead of direct allocation
		field = getLazyField(name, func() string {
			// Try fetching from query, params, form, or body
			if val := c.Request.URL.Query().Get(name); val != "" {
				return val
			}

			if val, ok := c.GetParam(name); ok {
				return val
			}

			if formData, ok := c.Values["formData"].(map[string]interface{}); ok {
				if val, ok := formData[name]; ok {
					return fmt.Sprintf("%v", val)
				}
			}

			if body, ok := c.Values["body"].(map[string]interface{}); ok {
				if val, ok := body[name]; ok {
					return fmt.Sprintf("%v", val)
				}
			}

			return ""
		})

		c.lazyFields[name] = field
	}

	return field
}

// In lazy_validation.go, update ValidateAllFields
// In lazy_validation.go, update ValidateAllFields
func (c *Context) ValidateAllFields() bool {
	if len(c.lazyFields) == 0 {
		return true
	}

	hasErrors := false

	for name, field := range c.lazyFields {
		_, err := field.Value()
		if err != nil {
			if c.ValidationErrs == nil {
				c.ValidationErrs = getValidationErrors()
				c.ValidationErrs = slices.Grow(c.ValidationErrs, len(c.lazyFields))
			}

			// More efficient approach - directly add to the slice
			if ve, ok := err.(*ValidationError); ok {
				c.ValidationErrs = append(c.ValidationErrs, ValidationError{
					Field: name,
					Err:   ve.Err,
				})
			} else {
				c.ValidationErrs = append(c.ValidationErrs, ValidationError{
					Field: name,
					Err:   err.Error(),
				})
			}

			hasErrors = true
		}
	}

	return !hasErrors
}

// ClearLazyFields efficiently clears the LazyFields map without reallocating.
func (c *Context) ClearLazyFields() {
	for k, field := range c.lazyFields {
		putLazyField(field)
		delete(c.lazyFields, k)
	}
}
