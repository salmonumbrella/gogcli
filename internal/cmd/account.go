package cmd

import (
	"os"
	"strings"
)

func requireAccount(flags *RootFlags) (string, error) {
	if v := strings.TrimSpace(flags.Account); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("GOG_ACCOUNT")); v != "" {
		return v, nil
	}
	return "", usage("missing --account (or set GOG_ACCOUNT)")
}
