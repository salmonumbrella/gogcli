package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
)

func newCalendarRespondCmd(flags *rootFlags) *cobra.Command {
	var status string
	var sendUpdates string

	cmd := &cobra.Command{
		Use:   "respond <calendarId> <eventId>",
		Short: "Respond to a meeting invitation (accept/decline/tentative)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := ui.FromContext(cmd.Context())
			account, err := requireAccount(flags)
			if err != nil {
				return err
			}
			calendarID := args[0]
			eventID := args[1]

			status = strings.TrimSpace(status)
			switch status {
			case "accepted", "declined", "tentative":
			default:
				return fmt.Errorf("invalid --status: %q (expected accepted|declined|tentative)", status)
			}

			sendUpdates = strings.TrimSpace(sendUpdates)
			switch sendUpdates {
			case "all", "none", "externalOnly":
			default:
				return fmt.Errorf("invalid --send-updates: %q (expected all|none|externalOnly)", sendUpdates)
			}

			svc, err := newCalendarService(cmd.Context(), account)
			if err != nil {
				return err
			}

			e, err := svc.Events.Get(calendarID, eventID).Do()
			if err != nil {
				return err
			}
			if e == nil || len(e.Attendees) == 0 {
				return errors.New("event has no attendees")
			}

			updatedAny := false
			for _, a := range e.Attendees {
				if a == nil {
					continue
				}
				if a.Self || strings.EqualFold(a.Email, account) {
					a.ResponseStatus = status
					updatedAny = true
				}
			}
			if !updatedAny {
				return errors.New("no attendee matches the authenticated user")
			}

			call := svc.Events.Update(calendarID, eventID, e)
			if sendUpdates != "none" {
				call = call.SendUpdates(sendUpdates)
			}
			updated, err := call.Do()
			if err != nil {
				return err
			}

			if outfmt.IsJSON(cmd.Context()) {
				return outfmt.WriteJSON(os.Stdout, map[string]any{"event": updated})
			}

			u.Out().Printf("id\t%s", updated.Id)
			u.Out().Printf("status\t%s", status)
			u.Out().Printf("send_updates\t%s", sendUpdates)
			if updated.HtmlLink != "" {
				u.Out().Printf("link\t%s", updated.HtmlLink)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "Response status: accepted|declined|tentative (required)")
	_ = cmd.MarkFlagRequired("status")
	cmd.Flags().StringVar(&sendUpdates, "send-updates", "none", "Send updates: all|none|externalOnly (default: none)")
	return cmd
}
