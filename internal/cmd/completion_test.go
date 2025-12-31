package cmd

import (
	"context"
	"strings"
	"testing"
)

func TestCompletionCmd(t *testing.T) {
	cases := []string{"bash", "zsh", "fish", "powershell"}
	for _, shell := range cases {
		shell := shell
		t.Run(shell, func(t *testing.T) {
			out := captureStdout(t, func() {
				cmd := &CompletionCmd{Shell: shell}
				if err := cmd.Run(context.Background()); err != nil {
					t.Fatalf("run: %v", err)
				}
			})
			if !strings.Contains(out, "Completion scripts not supported") {
				t.Fatalf("expected completion output, got %q", out)
			}
		})
	}
}
