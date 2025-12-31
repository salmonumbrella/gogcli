package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/ui"
	"golang.org/x/term"
)

func confirmDestructive(ctx context.Context, flags *RootFlags, action string) error {
	if flags.Force {
		return nil
	}

	// Never prompt in non-interactive contexts.
	if flags.NoInput || !term.IsTerminal(int(os.Stdin.Fd())) {
		return usagef("refusing to %s without --force (non-interactive)", action)
	}

	prompt := fmt.Sprintf("Proceed to %s? [y/N]: ", action)
	if u := ui.FromContext(ctx); u != nil {
		u.Err().Println(prompt)
	} else {
		_, _ = fmt.Fprintln(os.Stderr, prompt)
	}

	line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
	if readErr != nil && !errors.Is(readErr, os.ErrClosed) {
		return readErr
	}
	ans := strings.TrimSpace(strings.ToLower(line))
	if ans == "y" || ans == "yes" {
		return nil
	}
	return &ExitError{Code: 1, Err: errors.New("cancelled")}
}
