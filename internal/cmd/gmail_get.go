package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
)

type GmailGetCmd struct {
	MessageID string `arg:"" name:"messageId" help:"Message ID"`
	Format    string `name:"format" help:"Message format: full|metadata|raw" default:"full"`
	Headers   string `name:"headers" help:"Metadata headers (comma-separated; only for --format=metadata)"`
}

func (c *GmailGetCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)
	account, err := requireAccount(flags)
	if err != nil {
		return err
	}
	messageID := strings.TrimSpace(c.MessageID)
	if messageID == "" {
		return usage("empty messageId")
	}

	format := strings.TrimSpace(c.Format)
	if format == "" {
		format = "full"
	}
	switch format {
	case "full", "metadata", "raw":
	default:
		return fmt.Errorf("invalid --format: %q (expected full|metadata|raw)", format)
	}

	svc, err := newGmailService(ctx, account)
	if err != nil {
		return err
	}

	call := svc.Users.Messages.Get("me", messageID).Format(format).Context(ctx)
	if format == "metadata" {
		headerList := splitCSV(c.Headers)
		if len(headerList) == 0 {
			headerList = []string{"From", "To", "Subject", "Date"}
		}
		call = call.MetadataHeaders(headerList...)
	}

	msg, err := call.Do()
	if err != nil {
		return err
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(os.Stdout, map[string]any{"message": msg})
	}

	u.Out().Printf("id\t%s", msg.Id)
	u.Out().Printf("thread_id\t%s", msg.ThreadId)
	u.Out().Printf("label_ids\t%s", strings.Join(msg.LabelIds, ","))

	switch format {
	case "raw":
		if msg.Raw == "" {
			u.Err().Println("Empty raw message")
			return nil
		}
		decoded, err := base64.RawURLEncoding.DecodeString(msg.Raw)
		if err != nil {
			return err
		}
		u.Out().Println("")
		u.Out().Println(string(decoded))
		return nil
	case "metadata", "full":
		u.Out().Printf("from\t%s", headerValue(msg.Payload, "From"))
		u.Out().Printf("to\t%s", headerValue(msg.Payload, "To"))
		u.Out().Printf("subject\t%s", headerValue(msg.Payload, "Subject"))
		u.Out().Printf("date\t%s", headerValue(msg.Payload, "Date"))
		if format == "full" {
			body := bestBodyText(msg.Payload)
			if body != "" {
				u.Out().Println("")
				u.Out().Println(body)
			}
		}
		return nil
	default:
		return nil
	}
}
