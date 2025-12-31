package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

func TestGmailLabelsGetCmd_JSON(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/users/me/labels") || strings.HasSuffix(r.URL.Path, "/gmail/v1/users/me/labels"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"labels": []map[string]any{
					{"id": "INBOX", "name": "INBOX", "type": "system"},
					{"id": "Label_1", "name": "Custom", "type": "user"},
				},
			})
			return
		case strings.Contains(r.URL.Path, "/users/me/labels/") || strings.Contains(r.URL.Path, "/gmail/v1/users/me/labels/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			if id == "inbox" {
				// command should map name->id, but tolerate.
				id = "INBOX"
			}
			if id != "INBOX" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":             "INBOX",
				"name":           "INBOX",
				"type":           "system",
				"messagesTotal":  123,
				"messagesUnread": 7,
				"threadsTotal":   50,
				"threadsUnread":  3,
			})
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer srv.Close()

	svc, err := gmail.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	newGmailService = func(context.Context, string) (*gmail.Service, error) {
		return svc, nil
	}

	flags := &RootFlags{Account: "a@b.com"}

	out := captureStdout(t, func() {
		u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
		if uiErr != nil {
			t.Fatalf("ui.New: %v", uiErr)
		}
		ctx := ui.WithUI(context.Background(), u)
		ctx = outfmt.WithMode(ctx, outfmt.Mode{JSON: true})

		cmd := &GmailLabelsGetCmd{}
		if err := runKong(t, cmd, []string{"INBOX"}, ctx, flags); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	var parsed struct {
		Label struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			MessagesTotal  int64  `json:"messagesTotal"`
			MessagesUnread int64  `json:"messagesUnread"`
		} `json:"label"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse: %v\nout=%q", err, out)
	}
	if parsed.Label.ID != "INBOX" || parsed.Label.Name != "INBOX" {
		t.Fatalf("unexpected label: %#v", parsed.Label)
	}
	if parsed.Label.MessagesTotal != 123 || parsed.Label.MessagesUnread != 7 {
		t.Fatalf("unexpected counts: %#v", parsed.Label)
	}
}

func TestGmailLabelsListCmd_TextAndJSON(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/users/me/labels") || strings.HasSuffix(r.URL.Path, "/gmail/v1/users/me/labels"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"labels": []map[string]any{
					{"id": "INBOX", "name": "INBOX", "type": "system"},
					{"id": "Label_1", "name": "Custom", "type": "user"},
				},
			})
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer srv.Close()

	svc, err := gmail.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	newGmailService = func(context.Context, string) (*gmail.Service, error) { return svc, nil }

	flags := &RootFlags{Account: "a@b.com"}

	// Text output uses tabwriter to os.Stdout.
	textOut := captureStdout(t, func() {
		u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
		if uiErr != nil {
			t.Fatalf("ui.New: %v", uiErr)
		}
		ctx := ui.WithUI(context.Background(), u)
		ctx = outfmt.WithMode(ctx, outfmt.Mode{})

		cmd := &GmailLabelsListCmd{}
		if err := runKong(t, cmd, []string{}, ctx, flags); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})
	if !strings.Contains(textOut, "ID") || !strings.Contains(textOut, "NAME") {
		t.Fatalf("unexpected output: %q", textOut)
	}
	if !strings.Contains(textOut, "INBOX") || !strings.Contains(textOut, "Custom") {
		t.Fatalf("missing labels: %q", textOut)
	}

	jsonOut := captureStdout(t, func() {
		u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
		if uiErr != nil {
			t.Fatalf("ui.New: %v", uiErr)
		}
		ctx := ui.WithUI(context.Background(), u)
		ctx = outfmt.WithMode(ctx, outfmt.Mode{JSON: true})

		cmd := &GmailLabelsListCmd{}
		if err := runKong(t, cmd, []string{}, ctx, flags); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	var parsed struct {
		Labels []*gmail.Label `json:"labels"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatalf("json parse: %v\nout=%q", err, jsonOut)
	}
	if len(parsed.Labels) != 2 {
		t.Fatalf("unexpected labels: %#v", parsed.Labels)
	}
}

func TestGmailLabelsModifyCmd_JSON(t *testing.T) {
	origNew := newGmailService
	t.Cleanup(func() { newGmailService = origNew })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && (strings.HasSuffix(r.URL.Path, "/users/me/labels") || strings.HasSuffix(r.URL.Path, "/gmail/v1/users/me/labels")):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"labels": []map[string]any{
					{"id": "INBOX", "name": "INBOX", "type": "system"},
					{"id": "Label_1", "name": "Custom", "type": "user"},
				},
			})
			return
		case r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "/users/me/threads/") || strings.Contains(r.URL.Path, "/gmail/v1/users/me/threads/")) && strings.HasSuffix(r.URL.Path, "/modify"):
			parts := strings.Split(r.URL.Path, "/")
			threadID := parts[len(parts)-2]

			var body struct {
				AddLabelIds    []string `json:"addLabelIds"`
				RemoveLabelIds []string `json:"removeLabelIds"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.AddLabelIds) != 1 || body.AddLabelIds[0] != "INBOX" {
				http.Error(w, "bad addLabelIds", http.StatusBadRequest)
				return
			}
			if len(body.RemoveLabelIds) != 1 || body.RemoveLabelIds[0] != "Label_1" {
				http.Error(w, "bad removeLabelIds", http.StatusBadRequest)
				return
			}

			if threadID == "t2" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": 500, "message": "boom"},
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{})
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer srv.Close()

	svc, err := gmail.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	newGmailService = func(context.Context, string) (*gmail.Service, error) { return svc, nil }

	flags := &RootFlags{Account: "a@b.com"}

	out := captureStdout(t, func() {
		u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
		if uiErr != nil {
			t.Fatalf("ui.New: %v", uiErr)
		}
		ctx := ui.WithUI(context.Background(), u)
		ctx = outfmt.WithMode(ctx, outfmt.Mode{JSON: true})

		cmd := &GmailLabelsModifyCmd{}
		if err := runKong(t, cmd, []string{"t1", "t2", "--add", "INBOX", "--remove", "Custom"}, ctx, flags); err != nil {
			t.Fatalf("execute: %v", err)
		}
	})

	var parsed struct {
		Results []struct {
			ThreadID string `json:"threadId"`
			Success  bool   `json:"success"`
			Error    string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse: %v\nout=%q", err, out)
	}
	if len(parsed.Results) != 2 {
		t.Fatalf("unexpected results: %#v", parsed.Results)
	}
	if parsed.Results[0].ThreadID != "t1" || !parsed.Results[0].Success {
		t.Fatalf("unexpected result 0: %#v", parsed.Results[0])
	}
	if parsed.Results[1].ThreadID != "t2" || parsed.Results[1].Success || parsed.Results[1].Error == "" {
		t.Fatalf("unexpected result 1: %#v", parsed.Results[1])
	}
}

func TestFetchLabelIDToName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !(strings.HasSuffix(r.URL.Path, "/users/me/labels") || strings.HasSuffix(r.URL.Path, "/gmail/v1/users/me/labels")) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"labels": []map[string]any{
				{"id": "INBOX", "name": "INBOX", "type": "system"},
				{"id": "Label_1", "name": "Custom", "type": "user"},
				{"id": "Label_2", "type": "user"},
			},
		})
	}))
	defer srv.Close()

	svc, err := gmail.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	m, err := fetchLabelIDToName(svc)
	if err != nil {
		t.Fatalf("fetchLabelIDToName: %v", err)
	}
	if m["INBOX"] != "INBOX" {
		t.Fatalf("unexpected inbox: %q", m["INBOX"])
	}
	if m["Label_1"] != "Custom" {
		t.Fatalf("unexpected label1: %q", m["Label_1"])
	}
	// If name is missing, fall back to ID.
	if m["Label_2"] != "Label_2" {
		t.Fatalf("unexpected label2: %q", m["Label_2"])
	}
}
