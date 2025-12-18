package cmd

import (
	"strings"
	"testing"
)

func TestBuildRFC822Plain(t *testing.T) {
	raw, err := buildRFC822(mailOptions{
		From:    "a@b.com",
		To:      []string{"c@d.com"},
		Subject: "Hi",
		Body:    "Hello",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "Content-Type: text/plain") {
		t.Fatalf("missing content-type: %q", s)
	}
	if !strings.Contains(s, "\r\n\r\nHello\r\n") {
		t.Fatalf("missing body: %q", s)
	}
}

func TestBuildRFC822HTMLOnly(t *testing.T) {
	raw, err := buildRFC822(mailOptions{
		From:     "a@b.com",
		To:       []string{"c@d.com"},
		Subject:  "Hi",
		BodyHTML: "<p>Hello</p>",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "Content-Type: text/html") {
		t.Fatalf("missing content-type: %q", s)
	}
	if strings.Contains(s, "multipart/alternative") {
		t.Fatalf("unexpected multipart/alternative: %q", s)
	}
	if !strings.Contains(s, "<p>Hello</p>") {
		t.Fatalf("missing html body: %q", s)
	}
}

func TestBuildRFC822PlainAndHTMLAlternative(t *testing.T) {
	raw, err := buildRFC822(mailOptions{
		From:     "a@b.com",
		To:       []string{"c@d.com"},
		Subject:  "Hi",
		Body:     "Plain",
		BodyHTML: "<p>HTML</p>",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "multipart/alternative") {
		t.Fatalf("expected multipart/alternative: %q", s)
	}
	if !strings.Contains(s, "Content-Type: text/plain") || !strings.Contains(s, "Content-Type: text/html") {
		t.Fatalf("expected both text/plain and text/html parts: %q", s)
	}
	if !strings.Contains(s, "\r\n\r\nPlain\r\n") || !strings.Contains(s, "<p>HTML</p>") {
		t.Fatalf("missing bodies: %q", s)
	}
}

func TestBuildRFC822WithAttachment(t *testing.T) {
	raw, err := buildRFC822(mailOptions{
		From:    "a@b.com",
		To:      []string{"c@d.com"},
		Subject: "Hi",
		Body:    "Hello",
		Attachments: []mailAttachment{
			{Filename: "x.txt", MIMEType: "text/plain", Data: []byte("abc")},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "multipart/mixed") {
		t.Fatalf("expected multipart: %q", s)
	}
	if !strings.Contains(s, "Content-Disposition: attachment; filename=\"x.txt\"") {
		t.Fatalf("missing attachment header: %q", s)
	}
}

func TestBuildRFC822AlternativeWithAttachment(t *testing.T) {
	raw, err := buildRFC822(mailOptions{
		From:     "a@b.com",
		To:       []string{"c@d.com"},
		Subject:  "Hi",
		Body:     "Plain",
		BodyHTML: "<p>HTML</p>",
		Attachments: []mailAttachment{
			{Filename: "x.txt", MIMEType: "text/plain", Data: []byte("abc")},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "multipart/mixed") {
		t.Fatalf("expected multipart/mixed: %q", s)
	}
	if !strings.Contains(s, "multipart/alternative") {
		t.Fatalf("expected multipart/alternative: %q", s)
	}
	if !strings.Contains(s, "Content-Disposition: attachment; filename=\"x.txt\"") {
		t.Fatalf("missing attachment header: %q", s)
	}
	if !strings.Contains(s, "Content-Type: text/plain") || !strings.Contains(s, "Content-Type: text/html") {
		t.Fatalf("expected both text/plain and text/html parts: %q", s)
	}
}

func TestBuildRFC822UTF8Subject(t *testing.T) {
	raw, err := buildRFC822(mailOptions{
		From:    "a@b.com",
		To:      []string{"c@d.com"},
		Subject: "Grüße",
		Body:    "Hi",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "Subject: =?utf-8?") {
		t.Fatalf("expected encoded-word Subject: %q", s)
	}
}

func TestEncodeHeaderIfNeeded(t *testing.T) {
	if got := encodeHeaderIfNeeded("Hello"); got != "Hello" {
		t.Fatalf("unexpected: %q", got)
	}
	got := encodeHeaderIfNeeded("Grüße")
	if got == "Grüße" || !strings.Contains(got, "=?utf-8?") {
		t.Fatalf("expected encoded-word, got: %q", got)
	}
}

func TestContentDispositionFilename(t *testing.T) {
	if got := contentDispositionFilename("a.txt"); got != "filename=\"a.txt\"" {
		t.Fatalf("unexpected: %q", got)
	}
	got := contentDispositionFilename("Grüße.txt")
	if !strings.HasPrefix(got, "filename*=UTF-8''") {
		t.Fatalf("unexpected: %q", got)
	}
}
