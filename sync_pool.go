// Package nanite provides a lightweight, high-performance HTTP router for Go
// with optimized memory management through sync.Pool implementations.
package nanite

import (
	"bytes"
	"encoding/json"
	"sync"
)

//------------------------------------------------------------------------------
// Map Pool
//------------------------------------------------------------------------------

// mapPool is a pool of reusable map[string]interface{} objects.
// This reduces garbage collection pressure by reusing map allocations.
var mapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{}, 16)
	},
}

// getMap retrieves a map from the pool or creates a new one if necessary.
// The returned map is guaranteed to be empty and ready for use.
//
// Returns:
//   - map[string]interface{}: An empty map with pre-allocated capacity
func getMap() map[string]interface{} {
	m := mapPool.Get()
	if m == nil {
		// If the pool returns nil, create a new map with default capacity
		return make(map[string]interface{}, 16)
	}

	// Type assertion with ok check to handle unexpected types
	mapValue, ok := m.(map[string]interface{})
	if !ok {
		// If type assertion fails, create a new map
		return make(map[string]interface{}, 16)
	}

	return mapValue
}

// putMap returns a map to the pool after clearing its contents.
// This ensures the map is empty when it's reused.
//
// Parameters:
//   - m: The map to return to the pool
func putMap(m map[string]interface{}) {
	clear(m) // Clear the map to prevent memory leaks using go 1.21 feature clear()
	mapPool.Put(m)
}

//------------------------------------------------------------------------------
// Buffer Pool
//------------------------------------------------------------------------------

// bufferPool is a pool of reusable bytes.Buffer objects.
// Used primarily for efficient request body handling.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

//------------------------------------------------------------------------------
// Validation Error Pool
//------------------------------------------------------------------------------

// validationErrorPool is a pool of reusable ValidationError objects.
// This reduces allocations during request validation.
var validationErrorPool = sync.Pool{
	New: func() interface{} {
		return &ValidationError{}
	},
}

// getValidationError retrieves a ValidationError from the pool and initializes it.
//
// Parameters:
//   - field: The field name that failed validation
//   - errorMsg: The error message describing the validation failure
//
// Returns:
//   - *ValidationError: An initialized ValidationError
func getValidationError(field, errorMsg string) *ValidationError {
	ve := validationErrorPool.Get().(*ValidationError)
	ve.Field = field
	ve.Err = errorMsg
	return ve
}

// putValidationError returns a ValidationError to the pool after clearing its state.
//
// Parameters:
//   - ve: The ValidationError to return to the pool
func putValidationError(ve *ValidationError) {
	// Clear the fields to prevent memory leaks
	ve.Field = ""
	ve.Err = ""
	validationErrorPool.Put(ve)
}

//------------------------------------------------------------------------------
// ValidationErrors Slice Pool
//------------------------------------------------------------------------------

// validationErrorsPool is a pool of reusable ValidationErrors slices.
// This reduces allocations when collecting multiple validation errors.
var validationErrorsPool = sync.Pool{
	New: func() interface{} {
		return make(ValidationErrors, 0, 8)
	},
}

// getValidationErrors retrieves a ValidationErrors slice from the pool.
// The returned slice has zero length but pre-allocated capacity.
//
// Returns:
//   - ValidationErrors: An empty slice with pre-allocated capacity
func getValidationErrors() ValidationErrors {
	return validationErrorsPool.Get().(ValidationErrors)[:0]
}

// putValidationErrors returns a ValidationErrors slice to the pool.
//
// Parameters:
//   - ve: The ValidationErrors slice to return to the pool
func putValidationErrors(ve ValidationErrors) {
	if cap(ve) > 0 {
		validationErrorsPool.Put(ve[:0])
	}
}

//------------------------------------------------------------------------------
// LazyField Pool
//------------------------------------------------------------------------------

// lazyFieldPool is a pool of reusable LazyField objects.
// LazyFields are used for deferred validation of request parameters.
var lazyFieldPool = sync.Pool{
	New: func() interface{} {
		return &LazyField{
			rules: make([]ValidatorFunc, 0, 5),
		}
	},
}

// getLazyField retrieves a LazyField from the pool and initializes it.
//
// Parameters:
//   - name: The field name
//   - getValue: Function that retrieves the raw value from the request
//
// Returns:
//   - *LazyField: An initialized LazyField ready for validation rules
func getLazyField(name string, getValue func() string) *LazyField {
	lf := lazyFieldPool.Get().(*LazyField)
	lf.name = name
	lf.getValue = getValue
	lf.validated = false
	lf.value = ""
	lf.err = nil
	return lf
}

// putLazyField returns a LazyField to the pool after clearing its state.
// This prevents memory leaks from lingering references.
//
// Parameters:
//   - lf: The LazyField to return to the pool
func putLazyField(lf *LazyField) {
	lf.name = ""
	lf.getValue = nil
	lf.rules = lf.rules[:0]
	lf.validated = false
	lf.value = ""
	lf.err = nil
	lazyFieldPool.Put(lf)
}

//------------------------------------------------------------------------------
// ValidationChain Pool
//------------------------------------------------------------------------------

// validationChainPool is a pool of reusable ValidationChain objects.
// ValidationChains are used to build validation rules for request fields.
var validationChainPool = sync.Pool{
	New: func() interface{} {
		return &ValidationChain{
			rules: make([]ValidatorFunc, 0, 10), // Pre-allocate for efficiency
		}
	},
}

// getValidationChain retrieves a ValidationChain from the pool and initializes it.
//
// Parameters:
//   - field: The field name to validate
//
// Returns:
//   - *ValidationChain: An initialized ValidationChain ready for rules
func getValidationChain(field string) *ValidationChain {
	vc := validationChainPool.Get().(*ValidationChain)
	vc.field = field
	vc.rules = vc.rules[:0] // Clear but reuse the slice
	return vc
}

// putValidationChain returns a ValidationChain to the pool after clearing its state.
//
// Parameters:
//   - vc: The ValidationChain to return to the pool
func putValidationChain(vc *ValidationChain) {
	vc.field = ""
	vc.rules = vc.rules[:0]
	validationChainPool.Put(vc)
}

//------------------------------------------------------------------------------
// Utility Functions
//------------------------------------------------------------------------------

// cleanupNestedMaps iteratively cleans up nested maps and slices to prevent memory leaks.
// This function uses a stack-based approach to avoid recursion. Not currently used,
// this is intended for future use.
//
// Parameters:
//   - value: The root object to clean up (typically a map or slice)
func cleanupNestedMaps(value interface{}) {
	// Create a stack to hold values that need processing
	stack := make([]interface{}, 0, 8)
	stack = append(stack, value)

	// Process items until stack is empty
	for len(stack) > 0 {
		// Pop the last item from the stack
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Process maps
		if m, ok := current.(map[string]interface{}); ok {
			// Add all map values to the stack for processing
			for _, v := range m {
				if subMap, ok := v.(map[string]interface{}); ok {
					stack = append(stack, subMap)
				} else if arr, ok := v.([]interface{}); ok {
					stack = append(stack, arr)
				}
			}
			// Return the map to the pool
			putMap(m)
		} else if arr, ok := current.([]interface{}); ok {
			// Add all array elements to the stack for processing
			for _, v := range arr {
				if subMap, ok := v.(map[string]interface{}); ok {
					stack = append(stack, subMap)
				} else if subArr, ok := v.([]interface{}); ok {
					stack = append(stack, subArr)
				}
			}
		}
	}
}

//------------------------------------------------------------------------------
// JSON Encoder Pool
//------------------------------------------------------------------------------

// jsonEncoderBufferPair holds a reusable encoder and buffer pair
type jsonEncoderBufferPair struct {
	encoder *json.Encoder
	buffer  *bytes.Buffer
}

// jsonEncoderPool is a pool of reusable json.Encoder and buffer pairs
var jsonEncoderPool = sync.Pool{
	New: func() interface{} {
		buffer := new(bytes.Buffer)
		return &jsonEncoderBufferPair{
			encoder: json.NewEncoder(buffer),
			buffer:  buffer,
		}
	},
}

// getJSONEncoder retrieves an encoder/buffer pair from the pool
func getJSONEncoder() *jsonEncoderBufferPair {
	pair := jsonEncoderPool.Get().(*jsonEncoderBufferPair)
	pair.buffer.Reset()
	// Reconnect the encoder to the buffer after reset
	pair.encoder = json.NewEncoder(pair.buffer)
	return pair
}

// putJSONEncoder returns an encoder/buffer pair to the pool
func putJSONEncoder(pair *jsonEncoderBufferPair) {
	jsonEncoderPool.Put(pair)
}
