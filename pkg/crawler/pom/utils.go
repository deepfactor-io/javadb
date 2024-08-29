package pom

import (
	"strings"
)

func isProperty(version string) bool {
	if version != "" && strings.HasPrefix(version, "${") && strings.HasSuffix(version, "}") {
		return true
	}
	return false
}

func MergeMaps(parent, child map[string]string) map[string]string {
	merged := make(map[string]string)
	for k, v := range parent {
		merged[k] = v
	}
	for k, v := range child {
		merged[k] = v
	}
	return merged
}
