package cmd

import (
	"context"
	"strings"
	"testing"
)

func TestDriveCommand_ValidationErrors(t *testing.T) {
	flags := &RootFlags{Account: "a@b.com"}

	moveCmd := &DriveMoveCmd{}
	if err := runKong(t, moveCmd, []string{"file1"}, context.Background(), flags); err == nil || !strings.Contains(err.Error(), "missing --parent") {
		t.Fatalf("expected parent error, got %v", err)
	}

	shareCmd := &DriveShareCmd{}
	if err := runKong(t, shareCmd, []string{"file1"}, context.Background(), flags); err == nil || !strings.Contains(err.Error(), "must specify") {
		t.Fatalf("expected share validation error, got %v", err)
	}

	shareCmd = &DriveShareCmd{}
	if err := runKong(t, shareCmd, []string{"file1", "--anyone", "--role", "owner"}, context.Background(), flags); err == nil || !strings.Contains(err.Error(), "invalid --role") {
		t.Fatalf("expected role error, got %v", err)
	}
}

func TestDriveDeleteUnshare_NoInput(t *testing.T) {
	flags := &RootFlags{Account: "a@b.com", NoInput: true}

	deleteCmd := &DriveDeleteCmd{}
	if err := runKong(t, deleteCmd, []string{"file1"}, context.Background(), flags); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected refusing error, got %v", err)
	}

	unshareCmd := &DriveUnshareCmd{}
	if err := runKong(t, unshareCmd, []string{"file1", "perm1"}, context.Background(), flags); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected refusing error, got %v", err)
	}
}
