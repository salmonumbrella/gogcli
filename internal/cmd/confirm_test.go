package cmd

import (
	"context"
	"strings"
	"testing"
)

func TestConfirmDestructive_NoInput(t *testing.T) {
	flags := &RootFlags{NoInput: true}
	err := confirmDestructive(context.Background(), flags, "delete something")
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected refusing error, got %v", err)
	}
}

func TestConfirmDestructive_Force(t *testing.T) {
	flags := &RootFlags{Force: true}
	if err := confirmDestructive(context.Background(), flags, "delete something"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
