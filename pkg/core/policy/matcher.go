package policy

import (
	"path"
	"strings"
)

// MatchResource checks if a request path matches a resource pattern.
// Supports:
//   - Exact: /api/users
//   - Wildcard: /api/users/*
//   - Double wildcard: /api/**
func MatchResource(pattern, requestPath string) bool {
	// Normalize trailing slash
	pattern = strings.TrimRight(pattern, "/")
	requestPath = strings.TrimRight(requestPath, "/")

	if pattern == "" || requestPath == "" {
		return pattern == requestPath
	}

	// Handle ** (match any number of path segments)
	if strings.Contains(pattern, "**") {
		prefix := strings.SplitN(pattern, "**", 2)[0]
		prefix = strings.TrimRight(prefix, "/")
		if prefix == "" {
			return true // ** matches everything
		}
		return strings.HasPrefix(requestPath, prefix)
	}

	// Use path.Match for single-level wildcards
	matched, err := path.Match(pattern, requestPath)
	if err != nil {
		return false
	}
	return matched
}

// MatchMethod checks if a request method matches the policy methods list.
// Empty list means all methods are allowed.
func MatchMethod(policyMethods []string, requestMethod string) bool {
	if len(policyMethods) == 0 {
		return true
	}
	rm := strings.ToUpper(requestMethod)
	for _, m := range policyMethods {
		if strings.ToUpper(m) == rm {
			return true
		}
	}
	return false
}

// ACRSatisfies checks if the provided ACR meets or exceeds the required ACR
// according to the given ACR hierarchy.
//
// If hierarchy is empty, performs exact string comparison.
func ACRSatisfies(provided, required string, hierarchy []string) bool {
	if provided == required {
		return true
	}
	if len(hierarchy) == 0 {
		return false
	}

	providedIdx := indexOf(hierarchy, provided)
	requiredIdx := indexOf(hierarchy, required)

	if providedIdx < 0 || requiredIdx < 0 {
		// Fall back to exact match if not found in hierarchy
		return provided == required
	}

	return providedIdx >= requiredIdx
}

func indexOf(slice []string, val string) int {
	for i, v := range slice {
		if v == val {
			return i
		}
	}
	return -1
}
