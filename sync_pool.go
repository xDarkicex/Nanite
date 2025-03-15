// Package nanite provides sync.Pool implementations for various objects
// to reduce memory allocations and improve performance under high load.
package nanite

import (
	"bytes"
	"sync"
)

var mapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{}, 16)
	},
}

func getMap() map[string]interface{} {
	return mapPool.Get().(map[string]interface{})
}

func putMap(m map[string]interface{}) {
	for k := range m {
		delete(m, k)
	}
	mapPool.Put(m)
}

// ### Lazy field pool

// lazyFieldpool pool for lazy fields data
var lazyFieldPool = sync.Pool{
	New: func() interface{} {
		return &LazyField{
			rules: make([]ValidatorFunc, 0, 5),
		}
	},
}

// getLazyField retrieves a LazyField from the pool
func getLazyField(name string, getValue func() string) *LazyField {
	lf := lazyFieldPool.Get().(*LazyField)
	lf.name = name
	lf.getValue = getValue
	lf.validated = false
	lf.value = ""
	lf.err = nil
	return lf
}

// putLazyField returns a LazyField to the pool
func putLazyField(lf *LazyField) {
	lf.name = ""
	lf.getValue = nil
	lf.rules = lf.rules[:0]
	lf.validated = false
	lf.value = ""
	lf.err = nil
	lazyFieldPool.Put(lf)
}

// Object pool for ValidationError
var validationErrorPool = sync.Pool{
	New: func() interface{} {
		return &ValidationError{}
	},
}

// getValidationError retrieves a ValidationError from the pool
func getValidationError(field, errorMsg string) *ValidationError {
	ve := validationErrorPool.Get().(*ValidationError)
	ve.Field = field
	ve.Err = errorMsg
	return ve
}

// putValidationError returns a ValidationError to the pool
func putValidationError(ve *ValidationError) {
	// Clear the fields to prevent memory leaks
	ve.Field = ""
	ve.Err = ""
	validationErrorPool.Put(ve)
}

// Buffer Pool for ValidationMiddleware
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var validationErrorsPool = sync.Pool{
	New: func() interface{} {
		return make(ValidationErrors, 0, 8)
	},
}

func getValidationErrors() ValidationErrors {
	return validationErrorsPool.Get().(ValidationErrors)[:0]
}

func putValidationErrors(ve ValidationErrors) {
	if cap(ve) > 0 {
		validationErrorsPool.Put(ve[:0])
	}
}

var validationChainPool = sync.Pool{
	New: func() interface{} {
		return &ValidationChain{
			rules: make([]ValidatorFunc, 0, 5), // Pre-allocate for efficiency
		}
	},
}

// getValidationChain retrieves a ValidationChain from the pool
func getValidationChain(field string) *ValidationChain {
	vc := validationChainPool.Get().(*ValidationChain)
	vc.field = field
	vc.rules = vc.rules[:0] // Clear but reuse the slice
	return vc
}

// putValidationChain returns a ValidationChain to the pool
func putValidationChain(vc *ValidationChain) {
	vc.field = ""
	vc.rules = vc.rules[:0]
	validationChainPool.Put(vc)
}
