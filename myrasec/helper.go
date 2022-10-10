package myrasec

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseResourceServiceID splits the passed id (format like string:integer) to separate values
func parseResourceServiceID(id string) (string, int, error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", 0, fmt.Errorf("unexpected format of ID (%s), expected name:ID", id)
	}

	recordID, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("second part of ID is not an integer value (%s)", id)
	}

	return parts[0], recordID, nil
}

// StringInSlice checks if the haystack []string slice contains the passed needle string
func StringInSlice(needle string, haystack []string) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

// IntInSlice checks if the haystack []int slice contains the passed needle int
func IntInSlice(needle int, haystack []int) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

// formatError returns the error message with a timestamp appended to it
func formatError(err error) string {
	return fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339Nano), err.Error())
}
