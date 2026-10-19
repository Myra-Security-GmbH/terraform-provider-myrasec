package myrasec

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestListAccessPagesRejectsNonPositiveIDs(t *testing.T) {
	for _, id := range []int{0, -1} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			rows, err := listAccessPages(context.Background(), map[string]string{}, func(context.Context, map[string]string) ([]int, error) {
				return []int{1, id}, nil
			}, func(id int) int { return id })
			if err == nil || !strings.Contains(err.Error(), "without a positive ID") || rows != nil {
				t.Fatalf("rows=%v error=%v", rows, err)
			}
		})
	}
}
