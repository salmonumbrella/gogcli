package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

func TestDriveCommands_MoreCoverage(t *testing.T) {
	origNew := newDriveService
	t.Cleanup(func() { newDriveService = origNew })

	permCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/drive/v3")
		switch {
		case strings.Contains(path, "/files/") && strings.HasSuffix(path, "/copy") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "copy1",
				"name":        "Copy",
				"mimeType":    "text/plain",
				"webViewLink": "http://example.com/copy",
			})
			return
		case strings.Contains(path, "/files/") && strings.Contains(path, "/permissions/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			return
		case strings.Contains(path, "/files/") && strings.HasSuffix(path, "/permissions") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   "perm1",
				"type": "anyone",
				"role": "reader",
			})
			return
		case strings.Contains(path, "/files/") && strings.HasSuffix(path, "/permissions") && r.Method == http.MethodGet:
			permCalls++
			w.Header().Set("Content-Type", "application/json")
			if permCalls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"permissions": []map[string]any{},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"permissions":   []map[string]any{{"id": "perm1", "type": "user", "role": "reader", "emailAddress": "a@example.com"}},
				"nextPageToken": "next",
			})
			return
		case strings.HasPrefix(path, "/files/") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "file1",
				"name":        "File",
				"parents":     []string{"p-old"},
				"mimeType":    "text/plain",
				"webViewLink": "",
			})
			return
		case path == "/files" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "folder1",
				"name":        "Folder",
				"webViewLink": "http://example.com/folder",
			})
			return
		case strings.HasPrefix(path, "/files/") && r.Method == http.MethodPatch:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "file1",
				"name":        "Renamed",
				"parents":     []string{"p-new"},
				"webViewLink": "http://example.com/file",
			})
			return
		case strings.HasPrefix(path, "/files/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer srv.Close()

	svc, err := drive.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	newDriveService = func(context.Context, string) (*drive.Service, error) { return svc, nil }

	flags := &RootFlags{Account: "a@b.com", Force: true}
	u, uiErr := ui.New(ui.Options{Stdout: io.Discard, Stderr: io.Discard, Color: "never"})
	if uiErr != nil {
		t.Fatalf("ui.New: %v", uiErr)
	}
	ctx := ui.WithUI(context.Background(), u)
	jsonCtx := outfmt.WithMode(ctx, outfmt.Mode{JSON: true})

	// mkdir text
	mkdirCmd := &DriveMkdirCmd{}
	if err := runKong(t, mkdirCmd, []string{"Folder"}, ctx, flags); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// rename json
	jsonOut := captureStdout(t, func() {
		renameCmd := &DriveRenameCmd{}
		if err := runKong(t, renameCmd, []string{"file1", "Renamed"}, jsonCtx, flags); err != nil {
			t.Fatalf("rename: %v", err)
		}
	})
	if !strings.Contains(jsonOut, "Renamed") {
		t.Fatalf("unexpected rename json: %q", jsonOut)
	}

	// move json
	_ = captureStdout(t, func() {
		moveCmd := &DriveMoveCmd{}
		if err := runKong(t, moveCmd, []string{"file1", "--parent", "p-new"}, jsonCtx, flags); err != nil {
			t.Fatalf("move: %v", err)
		}
	})

	// share json (exercise fallback link)
	shareOut := captureStdout(t, func() {
		shareCmd := &DriveShareCmd{}
		if err := runKong(t, shareCmd, []string{"file1", "--anyone"}, jsonCtx, flags); err != nil {
			t.Fatalf("share: %v", err)
		}
	})
	if !strings.Contains(shareOut, "drive.google.com") {
		t.Fatalf("expected fallback link, got %q", shareOut)
	}

	// unshare text
	unshareCmd := &DriveUnshareCmd{}
	if err := runKong(t, unshareCmd, []string{"file1", "perm1"}, ctx, flags); err != nil {
		t.Fatalf("unshare: %v", err)
	}

	// permissions: first empty text, then json
	permissionsCmd := &DrivePermissionsCmd{}
	if err := runKong(t, permissionsCmd, []string{"file1"}, ctx, flags); err != nil {
		t.Fatalf("permissions text: %v", err)
	}
	_ = captureStdout(t, func() {
		permissionsCmd = &DrivePermissionsCmd{}
		if err := runKong(t, permissionsCmd, []string{"file1"}, jsonCtx, flags); err != nil {
			t.Fatalf("permissions json: %v", err)
		}
	})

	// copy json
	_ = captureStdout(t, func() {
		copyCmd := &DriveCopyCmd{}
		if err := runKong(t, copyCmd, []string{"file1", "Copy"}, jsonCtx, flags); err != nil {
			t.Fatalf("copy: %v", err)
		}
	})

	// delete json
	_ = captureStdout(t, func() {
		deleteCmd := &DriveDeleteCmd{}
		if err := runKong(t, deleteCmd, []string{"file1"}, jsonCtx, flags); err != nil {
			t.Fatalf("delete: %v", err)
		}
	})
}

func TestDriveCommands_TextOutput(t *testing.T) {
	origNew := newDriveService
	origDownload := driveDownload
	t.Cleanup(func() {
		newDriveService = origNew
		driveDownload = origDownload
	})

	driveDownload = func(context.Context, *drive.Service, string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("filedata")),
		}, nil
	}

	permCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/drive/v3")
		switch {
		case strings.Contains(path, "/files/") && strings.HasSuffix(path, "/copy") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "copy1",
				"name":        "Copy",
				"mimeType":    "text/plain",
				"webViewLink": "http://example.com/copy",
			})
			return
		case strings.Contains(path, "/files/") && strings.Contains(path, "/permissions/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			return
		case strings.Contains(path, "/files/") && strings.HasSuffix(path, "/permissions") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   "perm1",
				"type": "anyone",
				"role": "reader",
			})
			return
		case strings.Contains(path, "/files/") && strings.HasSuffix(path, "/permissions") && r.Method == http.MethodGet:
			permCalls++
			w.Header().Set("Content-Type", "application/json")
			if permCalls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"permissions": []map[string]any{},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"permissions":   []map[string]any{{"id": "perm1", "type": "user", "role": "reader", "emailAddress": "a@example.com"}},
				"nextPageToken": "next",
			})
			return
		case strings.HasPrefix(path, "/files/") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			id := strings.TrimPrefix(path, "/files/")
			resp := map[string]any{
				"id":           id,
				"name":         "File",
				"parents":      []string{"p-old"},
				"mimeType":     "text/plain",
				"webViewLink":  "",
				"size":         "1234",
				"modifiedTime": "2025-12-01T12:00:00Z",
				"createdTime":  "2025-12-01T10:00:00Z",
			}
			if id == "file1" {
				resp["webViewLink"] = "http://example.com/file"
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		case path == "/files" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "folder1",
				"name":        "Folder",
				"webViewLink": "http://example.com/folder",
				"mimeType":    "application/vnd.google-apps.folder",
			})
			return
		case strings.Contains(r.URL.Path, "/upload/drive/v3/files") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "upload1",
				"name":        "Upload",
				"mimeType":    "text/plain",
				"webViewLink": "http://example.com/upload",
			})
			return
		case strings.HasPrefix(path, "/files/") && r.Method == http.MethodPatch:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "file1",
				"name":        "Renamed",
				"parents":     []string{"p-new"},
				"webViewLink": "http://example.com/file",
			})
			return
		case strings.HasPrefix(path, "/files/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer srv.Close()

	svc, err := drive.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	newDriveService = func(context.Context, string) (*drive.Service, error) { return svc, nil }

	flags := &RootFlags{Account: "a@b.com", Force: true}
	uploadPath := filepath.Join(t.TempDir(), "upload.txt")
	if writeErr := os.WriteFile(uploadPath, []byte("data"), 0o600); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	downloadPath := filepath.Join(t.TempDir(), "download.bin")

	out := captureStdout(t, func() {
		u, uiErr := ui.New(ui.Options{Stdout: os.Stdout, Stderr: io.Discard, Color: "never"})
		if uiErr != nil {
			t.Fatalf("ui.New: %v", uiErr)
		}
		ctx := ui.WithUI(context.Background(), u)

		getCmd := &DriveGetCmd{}
		if err := runKong(t, getCmd, []string{"file1"}, ctx, flags); err != nil {
			t.Fatalf("get: %v", err)
		}

		downloadCmd := &DriveDownloadCmd{}
		if err := runKong(t, downloadCmd, []string{"file1", "--out", downloadPath}, ctx, flags); err != nil {
			t.Fatalf("download: %v", err)
		}

		uploadCmd := &DriveUploadCmd{}
		if err := runKong(t, uploadCmd, []string{uploadPath}, ctx, flags); err != nil {
			t.Fatalf("upload: %v", err)
		}

		renameCmd := &DriveRenameCmd{}
		if err := runKong(t, renameCmd, []string{"file1", "Renamed"}, ctx, flags); err != nil {
			t.Fatalf("rename: %v", err)
		}

		moveCmd := &DriveMoveCmd{}
		if err := runKong(t, moveCmd, []string{"file1", "--parent", "p-new"}, ctx, flags); err != nil {
			t.Fatalf("move: %v", err)
		}

		shareCmd := &DriveShareCmd{}
		if err := runKong(t, shareCmd, []string{"file1", "--anyone"}, ctx, flags); err != nil {
			t.Fatalf("share: %v", err)
		}

		unshareCmd := &DriveUnshareCmd{}
		if err := runKong(t, unshareCmd, []string{"file1", "perm1"}, ctx, flags); err != nil {
			t.Fatalf("unshare: %v", err)
		}

		copyCmd := &DriveCopyCmd{}
		if err := runKong(t, copyCmd, []string{"file1", "Copy"}, ctx, flags); err != nil {
			t.Fatalf("copy: %v", err)
		}

		deleteCmd := &DriveDeleteCmd{}
		if err := runKong(t, deleteCmd, []string{"file1"}, ctx, flags); err != nil {
			t.Fatalf("delete: %v", err)
		}
	})
	if !strings.Contains(out, "permission_id") || !strings.Contains(out, "deleted") {
		t.Fatalf("unexpected output: %q", out)
	}
}
