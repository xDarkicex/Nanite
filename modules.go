package nanite

import (
	"fmt"
	"strconv"
	"strings"
)

func (c *Context) GetIntParam(key string) (int, error) {
	val, ok := c.GetParam(key)
	if !ok {
		return 0, fmt.Errorf("parameter %s not found", key)
	}
	return strconv.Atoi(val)
}

func (c *Context) GetIntParamOrDefault(key string, defaultVal int) int {
	val, err := c.GetIntParam(key)
	if err != nil {
		return defaultVal
	}
	return val
}

func (c *Context) GetFloatParam(key string) (float64, error) {
	val, ok := c.GetParam(key)
	if !ok {
		return 0.0, fmt.Errorf("parameter %s not found", key)
	}
	return strconv.ParseFloat(val, 64)
}

func (c *Context) GetFloatParamOrDefault(key string, defaultVal float64) float64 {
	val, err := c.GetFloatParam(key)
	if err != nil {
		return defaultVal
	}
	return val
}

func (c *Context) GetBoolParam(key string) (bool, error) {
	val, ok := c.GetParam(key)
	if !ok {
		return false, fmt.Errorf("parameter %s not found", key)
	}
	return strconv.ParseBool(val)
}

func (c *Context) GetBoolParamOrDefault(key string, defaultVal bool) bool {
	val, err := c.GetBoolParam(key)
	if err != nil {
		return defaultVal
	}
	return val
}

func (c *Context) GetUintParam(key string) (uint64, error) {
	val, ok := c.GetParam(key)
	if !ok {
		return 0, fmt.Errorf("parameter %s not found", key)
	}
	return strconv.ParseUint(val, 10, 64)
}

func (c *Context) GetUintParamOrDefault(key string, defaultVal uint64) uint64 {
	val, err := c.GetUintParam(key)
	if err != nil {
		return defaultVal
	}
	return val
}

// GetStringParamOrDefault retrieves a route parameter as a string or returns the default value.
func (c *Context) GetStringParamOrDefault(key string, defaultVal string) string {
	val, ok := c.GetParam(key)
	if !ok || val == "" {
		return defaultVal
	}
	return val
}

// RouteInfo contains information about a registered route
type RouteInfo struct {
	Method     string // HTTP method (GET, POST, etc.)
	Path       string // Route path with parameters
	HasHandler bool   // Whether the route has a handler
	Middleware int    // Number of middleware functions
}

func (r *Router) ListRoutes() []RouteInfo {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var routes []RouteInfo

	// Process static routes first
	for method, pathMap := range r.staticRoutes {
		for path := range pathMap {
			routes = append(routes, RouteInfo{
				Method:     method,
				Path:       path,
				HasHandler: true,
				// Since middleware is wrapped in the handler, we can't determine the count
			})
		}
	}

	// Process radix tree routes
	for method, tree := range r.trees {
		collectRoutesFromTree(method, "/", tree, &routes)
	}

	return routes
}

// collectRoutesFromTree recursively collects routes from a radix tree node
func collectRoutesFromTree(method, path string, node *RadixNode, routes *[]RouteInfo) {
	// Current path including this node's prefix
	currentPath := path
	if path != "/" || node.prefix != "" {
		if path == "/" {
			currentPath = "/" + node.prefix
		} else {
			currentPath = path + node.prefix
		}
	}

	// Add this node if it has a handler
	if node.handler != nil {
		*routes = append(*routes, RouteInfo{
			Method:     method,
			Path:       currentPath,
			HasHandler: true,
		})
	}

	// Process parameter child
	if node.paramChild != nil {
		paramPath := currentPath
		if paramPath == "/" {
			paramPath = "/:" + node.paramChild.paramName
		} else if !strings.HasSuffix(paramPath, "/") {
			paramPath = paramPath + "/:" + node.paramChild.paramName
		} else {
			paramPath = paramPath + ":" + node.paramChild.paramName
		}
		collectRoutesFromTree(method, paramPath, node.paramChild, routes)
	}

	// Process wildcard child
	if node.wildcardChild != nil {
		wildcardPath := currentPath
		if wildcardPath == "/" {
			wildcardPath = "/*" + node.wildcardChild.wildcardName
		} else if !strings.HasSuffix(wildcardPath, "/") {
			wildcardPath = wildcardPath + "/*" + node.wildcardChild.wildcardName
		} else {
			wildcardPath = wildcardPath + "*" + node.wildcardChild.wildcardName
		}

		*routes = append(*routes, RouteInfo{
			Method:     method,
			Path:       wildcardPath,
			HasHandler: node.wildcardChild.handler != nil,
		})
	}

	// Process regular children
	for _, child := range node.children {
		collectRoutesFromTree(method, currentPath, child, routes)
	}
}
