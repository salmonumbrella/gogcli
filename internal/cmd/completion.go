package cmd

import (
	"context"
	"fmt"
	"os"
)

type CompletionCmd struct {
	Shell string `arg:"" name:"shell" help:"Shell (bash|zsh|fish|powershell)" enum:"bash,zsh,fish,powershell"`
}

func (c *CompletionCmd) Run(_ context.Context) error {
	_, err := fmt.Fprintf(os.Stdout, "Completion scripts not supported in this build (%s).\n", c.Shell)
	return err
}
