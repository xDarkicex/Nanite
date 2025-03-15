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
		rawValue := lf.getValue() // Fetch the raw value
		lf.value = rawValue
		for _, rule := range lf.rules {
			if err := rule(rawValue); err != nil {
				lf.err = fmt.Errorf("%s: %w", lf.name, err)
				break
			}
		}
		lf.validated = true
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
				return c.Request.FormValue(name) // Example: fetch from form data
			},
		}
		c.lazyFields[name] = field
	}
	return field
}
