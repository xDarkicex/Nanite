package nanite

import "fmt"

type LazyField struct {
	name      string          // The field's name (e.g., "username")
	getValue  func() string   // Function to fetch the raw value from the request
	rules     []ValidatorFunc // List of validation rules (e.g., regex checks)
	validated bool            // Tracks if validation has run
	value     string          // Stores the validated value
	err       error           // Stores any validation error
}

func (lf *LazyField) Value() (string, error) {
	if !lf.validated {
		rawValue := lf.getValue()
		lf.value = rawValue
		for _, rule := range lf.rules {
			if err := rule(rawValue); err != nil {
				ve := getValidationError(lf.name, err.Error())
				lf.err = ve
				break
			}
		}
		lf.validated = true
	}
	if lf.err != nil {
		if ve, ok := lf.err.(*ValidationError); ok {
			defer putValidationError(ve)
		}
	}
	return lf.value, lf.err
}

func (c *Context) Field(name string) *LazyField {
	// Safety net: initialize lazyFields if nil
	if c.lazyFields == nil {
		c.lazyFields = make(map[string]*LazyField)
	}
	field, exists := c.lazyFields[name]
	if !exists {
		field = &LazyField{
			name: name,
			getValue: func() string {
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
			},
		}
		c.lazyFields[name] = field
	}
	return field
}
