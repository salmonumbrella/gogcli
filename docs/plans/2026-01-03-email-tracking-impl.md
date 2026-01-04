# Email Tracking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add optional email open tracking to gogcli using Cloudflare Workers + D1.

**Architecture:** Self-hosted tracking via Cloudflare Worker that serves pixels and logs opens to D1. CLI encrypts pixel payloads (AES-GCM), injects into HTML emails, and queries the Worker for open data. Free tier supports 100K opens/day.

**Tech Stack:** Go (CLI), TypeScript (Worker), Cloudflare D1 (SQLite), AES-GCM encryption, wrangler CLI

---

## Phase 1: Cloudflare Worker

### Task 1: Create Worker Project Structure

**Files:**
- Create: `internal/tracking/worker/src/index.ts`
- Create: `internal/tracking/worker/src/crypto.ts`
- Create: `internal/tracking/worker/src/types.ts`
- Create: `internal/tracking/worker/wrangler.toml`
- Create: `internal/tracking/worker/package.json`
- Create: `internal/tracking/worker/tsconfig.json`

**Step 1: Create directory structure**

```bash
mkdir -p internal/tracking/worker/src
```

**Step 2: Create package.json**

```json
{
  "name": "gog-email-tracker",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest"
  },
  "devDependencies": {
    "@cloudflare/workers-types": "^4.20241230.0",
    "typescript": "^5.3.3",
    "wrangler": "^3.99.0",
    "vitest": "^2.1.8"
  }
}
```

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "types": ["@cloudflare/workers-types"],
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"]
}
```

**Step 4: Create wrangler.toml template**

```toml
name = "gog-email-tracker"
main = "src/index.ts"
compatibility_date = "2024-12-01"

[[d1_databases]]
binding = "DB"
database_name = "gog-email-tracker"
database_id = "placeholder-will-be-replaced"
```

**Step 5: Create types.ts**

```typescript
export interface Env {
  DB: D1Database;
  TRACKING_KEY: string;
  ADMIN_KEY: string;
}

export interface PixelPayload {
  r: string;  // recipient
  s: string;  // subject hash (first 6 chars)
  t: number;  // sent timestamp (unix)
}

export interface OpenRecord {
  id: number;
  recipient: string;
  subject_hash: string;
  sent_at: string;
  opened_at: string;
  ip: string;
  user_agent: string;
  country: string | null;
  region: string | null;
  city: string | null;
  timezone: string | null;
  is_bot: number;
  bot_type: string | null;
}
```

**Step 6: Commit**

```bash
git add internal/tracking/worker/
git commit -m "feat(tracking): scaffold worker project structure"
```

---

### Task 2: Implement AES-GCM Crypto Module

**Files:**
- Create: `internal/tracking/worker/src/crypto.ts`
- Create: `internal/tracking/worker/src/crypto.test.ts`

**Step 1: Write crypto.ts**

```typescript
import type { PixelPayload } from './types';

const ALGORITHM = 'AES-GCM';
const IV_LENGTH = 12;

export async function importKey(base64Key: string): Promise<CryptoKey> {
  const keyBytes = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: ALGORITHM },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function decrypt(blob: string, key: CryptoKey): Promise<PixelPayload> {
  // URL-safe base64 decode
  const base64 = blob.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const combined = Uint8Array.from(atob(padded), c => c.charCodeAt(0));

  const iv = combined.slice(0, IV_LENGTH);
  const ciphertext = combined.slice(IV_LENGTH);

  const decrypted = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv },
    key,
    ciphertext
  );

  const text = new TextDecoder().decode(decrypted);
  return JSON.parse(text) as PixelPayload;
}

export async function encrypt(payload: PixelPayload, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(JSON.stringify(payload));

  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv },
    key,
    encoded
  );

  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);

  // URL-safe base64 encode
  const base64 = btoa(String.fromCharCode(...combined));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

**Step 2: Write crypto.test.ts**

```typescript
import { describe, it, expect } from 'vitest';
import { importKey, encrypt, decrypt } from './crypto';

describe('crypto', () => {
  const testKey = 'MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE='; // 32 bytes base64

  it('encrypts and decrypts payload', async () => {
    const key = await importKey(testKey);
    const payload = { r: 'test@example.com', s: 'abc123', t: 1704067200 };

    const encrypted = await encrypt(payload, key);
    const decrypted = await decrypt(encrypted, key);

    expect(decrypted).toEqual(payload);
  });

  it('produces URL-safe base64', async () => {
    const key = await importKey(testKey);
    const payload = { r: 'test@example.com', s: 'abc123', t: 1704067200 };

    const encrypted = await encrypt(payload, key);

    expect(encrypted).not.toMatch(/[+/=]/);
  });

  it('throws on invalid ciphertext', async () => {
    const key = await importKey(testKey);

    await expect(decrypt('invalid', key)).rejects.toThrow();
  });
});
```

**Step 3: Run tests**

```bash
cd internal/tracking/worker && npm install && npm test
```

Expected: All 3 tests pass

**Step 4: Commit**

```bash
git add internal/tracking/worker/src/crypto.ts internal/tracking/worker/src/crypto.test.ts
git commit -m "feat(tracking): implement AES-GCM encryption for pixel URLs"
```

---

### Task 3: Implement Bot Detection

**Files:**
- Create: `internal/tracking/worker/src/bot.ts`
- Create: `internal/tracking/worker/src/bot.test.ts`

**Step 1: Write bot.ts**

```typescript
export interface BotDetectionResult {
  isBot: boolean;
  botType: string | null;
}

// Apple Private Relay IP ranges (simplified - real impl would use full list)
const APPLE_RELAY_PREFIXES = [
  '17.', // Apple corporate
  '104.28.', // Cloudflare for Apple
];

export function detectBot(
  userAgent: string,
  ip: string,
  timeSinceDeliveryMs: number | null
): BotDetectionResult {
  // Gmail Image Proxy = real human (Gmail proxies on their behalf)
  if (userAgent.includes('GoogleImageProxy')) {
    return { isBot: false, botType: 'gmail_proxy' };
  }

  // Apple Mail Privacy Protection
  if (APPLE_RELAY_PREFIXES.some(prefix => ip.startsWith(prefix))) {
    return { isBot: true, botType: 'apple_mpp' };
  }

  // Outlook prefetch
  if (userAgent.includes('Outlook-iOS') ||
      userAgent.includes('Microsoft Outlook') ||
      userAgent.includes('ms-office')) {
    return { isBot: true, botType: 'outlook_prefetch' };
  }

  // Time-based detection: opens < 2 seconds after delivery are suspicious
  if (timeSinceDeliveryMs !== null && timeSinceDeliveryMs < 2000) {
    return { isBot: true, botType: 'prefetch' };
  }

  // Security scanners
  if (userAgent.includes('Barracuda') ||
      userAgent.includes('Symantec') ||
      userAgent.includes('Proofpoint')) {
    return { isBot: true, botType: 'security_scanner' };
  }

  return { isBot: false, botType: null };
}
```

**Step 2: Write bot.test.ts**

```typescript
import { describe, it, expect } from 'vitest';
import { detectBot } from './bot';

describe('detectBot', () => {
  it('treats GoogleImageProxy as real human', () => {
    const result = detectBot('GoogleImageProxy', '66.249.88.1', null);
    expect(result.isBot).toBe(false);
    expect(result.botType).toBe('gmail_proxy');
  });

  it('detects Apple Mail Privacy Protection', () => {
    const result = detectBot('Mozilla/5.0', '17.253.144.10', null);
    expect(result.isBot).toBe(true);
    expect(result.botType).toBe('apple_mpp');
  });

  it('detects Outlook prefetch', () => {
    const result = detectBot('Microsoft Outlook 16.0', '1.2.3.4', null);
    expect(result.isBot).toBe(true);
    expect(result.botType).toBe('outlook_prefetch');
  });

  it('detects rapid opens as prefetch', () => {
    const result = detectBot('Mozilla/5.0', '1.2.3.4', 500);
    expect(result.isBot).toBe(true);
    expect(result.botType).toBe('prefetch');
  });

  it('treats normal opens as human', () => {
    const result = detectBot('Mozilla/5.0 Chrome', '1.2.3.4', 5000);
    expect(result.isBot).toBe(false);
    expect(result.botType).toBeNull();
  });
});
```

**Step 3: Run tests**

```bash
cd internal/tracking/worker && npm test
```

Expected: All tests pass

**Step 4: Commit**

```bash
git add internal/tracking/worker/src/bot.ts internal/tracking/worker/src/bot.test.ts
git commit -m "feat(tracking): implement bot detection with time-based filtering"
```

---

### Task 4: Implement Worker Main Handler

**Files:**
- Create: `internal/tracking/worker/src/index.ts`
- Create: `internal/tracking/worker/src/pixel.ts`

**Step 1: Create pixel.ts with transparent GIF**

```typescript
// 1x1 transparent GIF (43 bytes)
export const TRANSPARENT_GIF = new Uint8Array([
  0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
  0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
  0x01, 0x00, 0x3b,
]);

export function pixelResponse(): Response {
  return new Response(TRANSPARENT_GIF, {
    headers: {
      'Content-Type': 'image/gif',
      'Content-Length': TRANSPARENT_GIF.length.toString(),
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    },
  });
}
```

**Step 2: Create index.ts with main handler**

```typescript
import type { Env, PixelPayload } from './types';
import { importKey, decrypt } from './crypto';
import { detectBot } from './bot';
import { pixelResponse } from './pixel';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Pixel endpoint: GET /p/:blob.gif
      if (path.startsWith('/p/') && path.endsWith('.gif')) {
        return await handlePixel(request, env, path);
      }

      // Query endpoint: GET /q/:blob
      if (path.startsWith('/q/')) {
        return await handleQuery(request, env, path);
      }

      // Admin opens endpoint: GET /opens
      if (path === '/opens') {
        return await handleAdminOpens(request, env, url);
      }

      // Health check
      if (path === '/health') {
        return new Response('ok', { status: 200 });
      }

      return new Response('Not Found', { status: 404 });
    } catch (error) {
      console.error('Handler error:', error);
      return new Response('Internal Error', { status: 500 });
    }
  },
};

async function handlePixel(request: Request, env: Env, path: string): Promise<Response> {
  // Extract blob from /p/:blob.gif
  const blob = path.slice(3, -4); // Remove '/p/' and '.gif'

  const key = await importKey(env.TRACKING_KEY);
  let payload: PixelPayload;

  try {
    payload = await decrypt(blob, key);
  } catch {
    // Still return pixel even if decryption fails (don't break email display)
    return pixelResponse();
  }

  // Get request metadata
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  const cf = (request as any).cf || {};

  // Calculate time since delivery
  const now = Date.now();
  const sentAt = payload.t * 1000; // Convert to ms
  const timeSinceDelivery = now - sentAt;

  // Detect bots
  const { isBot, botType } = detectBot(userAgent, ip, timeSinceDelivery);

  // Log to D1
  await env.DB.prepare(`
    INSERT INTO opens (
      recipient, subject_hash, sent_at, opened_at,
      ip, user_agent, country, region, city, timezone,
      is_bot, bot_type
    ) VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    payload.r,
    payload.s,
    new Date(sentAt).toISOString(),
    ip,
    userAgent,
    cf.country || null,
    cf.region || null,
    cf.city || null,
    cf.timezone || null,
    isBot ? 1 : 0,
    botType
  ).run();

  return pixelResponse();
}

async function handleQuery(request: Request, env: Env, path: string): Promise<Response> {
  const blob = path.slice(3); // Remove '/q/'

  const key = await importKey(env.TRACKING_KEY);
  let payload: PixelPayload;

  try {
    payload = await decrypt(blob, key);
  } catch {
    return new Response('Invalid tracking ID', { status: 400 });
  }

  const result = await env.DB.prepare(`
    SELECT
      opened_at, ip, city, region, country, timezone, is_bot, bot_type
    FROM opens
    WHERE recipient = ? AND subject_hash = ? AND sent_at = ?
    ORDER BY opened_at ASC
  `).bind(
    payload.r,
    payload.s,
    new Date(payload.t * 1000).toISOString()
  ).all();

  const opens = result.results.map((row: any) => ({
    at: row.opened_at,
    is_bot: row.is_bot === 1,
    bot_type: row.bot_type,
    location: row.city ? {
      city: row.city,
      region: row.region,
      country: row.country,
      timezone: row.timezone,
    } : null,
  }));

  const humanOpens = opens.filter((o: any) => !o.is_bot);

  return Response.json({
    recipient: payload.r,
    sent_at: new Date(payload.t * 1000).toISOString(),
    opens,
    total_opens: opens.length,
    human_opens: humanOpens.length,
    first_human_open: humanOpens[0] || null,
  });
}

async function handleAdminOpens(request: Request, env: Env, url: URL): Promise<Response> {
  // Verify admin key
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || authHeader !== `Bearer ${env.ADMIN_KEY}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const recipient = url.searchParams.get('recipient');
  const since = url.searchParams.get('since');
  const limit = parseInt(url.searchParams.get('limit') || '100', 10);

  let query = 'SELECT * FROM opens WHERE 1=1';
  const params: any[] = [];

  if (recipient) {
    query += ' AND recipient = ?';
    params.push(recipient);
  }

  if (since) {
    query += ' AND opened_at >= ?';
    params.push(since);
  }

  query += ' ORDER BY opened_at DESC LIMIT ?';
  params.push(limit);

  const result = await env.DB.prepare(query).bind(...params).all();

  return Response.json({
    opens: result.results.map((row: any) => ({
      recipient: row.recipient,
      subject_hash: row.subject_hash,
      sent_at: row.sent_at,
      opened_at: row.opened_at,
      is_bot: row.is_bot === 1,
      bot_type: row.bot_type,
      location: row.city ? {
        city: row.city,
        region: row.region,
        country: row.country,
      } : null,
    })),
  });
}
```

**Step 3: Commit**

```bash
git add internal/tracking/worker/src/
git commit -m "feat(tracking): implement worker with pixel, query, and admin endpoints"
```

---

### Task 5: Create D1 Schema

**Files:**
- Create: `internal/tracking/worker/schema.sql`

**Step 1: Write schema.sql**

```sql
-- Email tracking opens table
CREATE TABLE IF NOT EXISTS opens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  -- Decrypted from pixel payload
  recipient TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  sent_at TEXT NOT NULL,

  -- Recorded on open
  opened_at TEXT NOT NULL DEFAULT (datetime('now')),
  ip TEXT,
  user_agent TEXT,

  -- Geolocation (from Cloudflare request.cf)
  country TEXT,
  region TEXT,
  city TEXT,
  timezone TEXT,

  -- Bot detection
  is_bot INTEGER NOT NULL DEFAULT 0,
  bot_type TEXT
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_opens_recipient ON opens(recipient);
CREATE INDEX IF NOT EXISTS idx_opens_sent_at ON opens(sent_at);
CREATE INDEX IF NOT EXISTS idx_opens_opened_at ON opens(opened_at);
CREATE INDEX IF NOT EXISTS idx_opens_recipient_subject ON opens(recipient, subject_hash, sent_at);
```

**Step 2: Commit**

```bash
git add internal/tracking/worker/schema.sql
git commit -m "feat(tracking): add D1 schema for opens table"
```

---

## Phase 2: CLI Integration

### Task 6: Add Tracking Config

**Files:**
- Create: `internal/tracking/config.go`
- Create: `internal/tracking/config_test.go`

**Step 1: Write config.go**

```go
package tracking

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds tracking configuration
type Config struct {
	Enabled     bool   `json:"enabled"`
	WorkerURL   string `json:"worker_url"`
	TrackingKey string `json:"tracking_key"`
	AdminKey    string `json:"admin_key"`
}

// ConfigPath returns the path to the tracking config file
func ConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "gog", "tracking.json"), nil
}

// LoadConfig loads tracking configuration from disk
func LoadConfig() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Enabled: false}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// SaveConfig saves tracking configuration to disk
func SaveConfig(cfg *Config) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// IsConfigured returns true if tracking is set up
func (c *Config) IsConfigured() bool {
	return c.Enabled && c.WorkerURL != "" && c.TrackingKey != ""
}
```

**Step 2: Write config_test.go**

```go
package tracking

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	// Use temp dir
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg := &Config{
		Enabled:     true,
		WorkerURL:   "https://test.workers.dev",
		TrackingKey: "testkey123",
		AdminKey:    "adminkey456",
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.WorkerURL != cfg.WorkerURL {
		t.Errorf("WorkerURL mismatch: got %q, want %q", loaded.WorkerURL, cfg.WorkerURL)
	}
	if loaded.TrackingKey != cfg.TrackingKey {
		t.Errorf("TrackingKey mismatch: got %q, want %q", loaded.TrackingKey, cfg.TrackingKey)
	}
	if !loaded.IsConfigured() {
		t.Error("IsConfigured should return true")
	}
}

func TestLoadConfigMissing(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Enabled {
		t.Error("Expected Enabled to be false for missing config")
	}
	if cfg.IsConfigured() {
		t.Error("IsConfigured should return false for missing config")
	}
}
```

**Step 3: Run tests**

```bash
go test ./internal/tracking/... -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add internal/tracking/
git commit -m "feat(tracking): add config management"
```

---

### Task 7: Implement AES-GCM Crypto in Go

**Files:**
- Create: `internal/tracking/crypto.go`
- Create: `internal/tracking/crypto_test.go`

**Step 1: Write crypto.go**

```go
package tracking

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// PixelPayload is the data encoded in tracking pixel URLs
type PixelPayload struct {
	Recipient   string `json:"r"`
	SubjectHash string `json:"s"`
	SentAt      int64  `json:"t"`
}

// Encrypt encrypts a payload using AES-GCM and returns URL-safe base64
func Encrypt(payload *PixelPayload, keyBase64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Encode payload as JSON
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	// URL-safe base64 encode
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a URL-safe base64 blob using AES-GCM
func Decrypt(blob string, keyBase64 string) (*PixelPayload, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var payload PixelPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	return &payload, nil
}

// GenerateKey generates a new 256-bit AES key as base64
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
```

**Step 2: Write crypto_test.go**

```go
package tracking

import (
	"testing"
	"time"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	payload := &PixelPayload{
		Recipient:   "test@example.com",
		SubjectHash: "abc123",
		SentAt:      time.Now().Unix(),
	}

	encrypted, err := Encrypt(payload, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted.Recipient != payload.Recipient {
		t.Errorf("Recipient mismatch: got %q, want %q", decrypted.Recipient, payload.Recipient)
	}
	if decrypted.SubjectHash != payload.SubjectHash {
		t.Errorf("SubjectHash mismatch: got %q, want %q", decrypted.SubjectHash, payload.SubjectHash)
	}
	if decrypted.SentAt != payload.SentAt {
		t.Errorf("SentAt mismatch: got %d, want %d", decrypted.SentAt, payload.SentAt)
	}
}

func TestEncryptProducesURLSafeOutput(t *testing.T) {
	key, _ := GenerateKey()
	payload := &PixelPayload{
		Recipient:   "test@example.com",
		SubjectHash: "abc123",
		SentAt:      time.Now().Unix(),
	}

	encrypted, err := Encrypt(payload, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// URL-safe base64 should not contain +, /, or =
	for _, c := range encrypted {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("Output contains non-URL-safe character: %c", c)
		}
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	payload := &PixelPayload{
		Recipient:   "test@example.com",
		SubjectHash: "abc123",
		SentAt:      time.Now().Unix(),
	}

	encrypted, _ := Encrypt(payload, key1)

	_, err := Decrypt(encrypted, key2)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}
```

**Step 3: Run tests**

```bash
go test ./internal/tracking/... -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add internal/tracking/crypto.go internal/tracking/crypto_test.go
git commit -m "feat(tracking): implement AES-GCM encryption in Go"
```

---

### Task 8: Implement Pixel URL Generation

**Files:**
- Create: `internal/tracking/pixel.go`
- Create: `internal/tracking/pixel_test.go`

**Step 1: Write pixel.go**

```go
package tracking

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// GeneratePixelURL creates a tracking pixel URL for an email
func GeneratePixelURL(cfg *Config, recipient, subject string) (string, string, error) {
	if !cfg.IsConfigured() {
		return "", "", fmt.Errorf("tracking not configured")
	}

	// Hash subject (first 6 chars)
	subjectHash := hashSubject(subject)

	payload := &PixelPayload{
		Recipient:   recipient,
		SubjectHash: subjectHash,
		SentAt:      time.Now().Unix(),
	}

	blob, err := Encrypt(payload, cfg.TrackingKey)
	if err != nil {
		return "", "", fmt.Errorf("encrypt payload: %w", err)
	}

	pixelURL := fmt.Sprintf("%s/p/%s.gif", cfg.WorkerURL, blob)
	return pixelURL, blob, nil
}

// GeneratePixelHTML returns HTML img tag for the tracking pixel
func GeneratePixelHTML(pixelURL string) string {
	return fmt.Sprintf(
		`<img src="%s" width="1" height="1" style="display:none;width:1px;height:1px;border:0;" alt="" />`,
		pixelURL,
	)
}

func hashSubject(subject string) string {
	h := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(h[:])[:6]
}
```

**Step 2: Write pixel_test.go**

```go
package tracking

import (
	"strings"
	"testing"
)

func TestGeneratePixelURL(t *testing.T) {
	key, _ := GenerateKey()
	cfg := &Config{
		Enabled:     true,
		WorkerURL:   "https://test.workers.dev",
		TrackingKey: key,
	}

	pixelURL, blob, err := GeneratePixelURL(cfg, "test@example.com", "Hello World")
	if err != nil {
		t.Fatalf("GeneratePixelURL failed: %v", err)
	}

	if !strings.HasPrefix(pixelURL, "https://test.workers.dev/p/") {
		t.Errorf("Unexpected URL prefix: %s", pixelURL)
	}
	if !strings.HasSuffix(pixelURL, ".gif") {
		t.Errorf("URL should end with .gif: %s", pixelURL)
	}
	if blob == "" {
		t.Error("Blob should not be empty")
	}
}

func TestGeneratePixelURLNotConfigured(t *testing.T) {
	cfg := &Config{Enabled: false}

	_, _, err := GeneratePixelURL(cfg, "test@example.com", "Hello")
	if err == nil {
		t.Error("Expected error for unconfigured tracking")
	}
}

func TestGeneratePixelHTML(t *testing.T) {
	html := GeneratePixelHTML("https://test.workers.dev/p/abc123.gif")

	if !strings.Contains(html, `src="https://test.workers.dev/p/abc123.gif"`) {
		t.Errorf("HTML missing src: %s", html)
	}
	if !strings.Contains(html, `width="1"`) {
		t.Errorf("HTML missing width: %s", html)
	}
	if !strings.Contains(html, `style="display:none`) {
		t.Errorf("HTML missing display:none: %s", html)
	}
}

func TestHashSubjectConsistent(t *testing.T) {
	h1 := hashSubject("Hello World")
	h2 := hashSubject("Hello World")
	h3 := hashSubject("Different Subject")

	if h1 != h2 {
		t.Error("Same subject should produce same hash")
	}
	if h1 == h3 {
		t.Error("Different subjects should produce different hashes")
	}
	if len(h1) != 6 {
		t.Errorf("Hash should be 6 chars, got %d", len(h1))
	}
}
```

**Step 3: Run tests**

```bash
go test ./internal/tracking/... -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add internal/tracking/pixel.go internal/tracking/pixel_test.go
git commit -m "feat(tracking): add pixel URL generation"
```

---

### Task 9: Add --track Flag to gmail send

**Files:**
- Modify: `internal/cmd/gmail_send.go`
- Modify: `internal/cmd/gmail_mime.go`

**Step 1: Add Track field to GmailSendCmd**

In `internal/cmd/gmail_send.go`, add to struct:

```go
type GmailSendCmd struct {
	To               string   `name:"to" help:"Recipients (comma-separated, required)"`
	Cc               string   `name:"cc" help:"CC recipients (comma-separated)"`
	Bcc              string   `name:"bcc" help:"BCC recipients (comma-separated)"`
	Subject          string   `name:"subject" help:"Subject (required)"`
	Body             string   `name:"body" help:"Body (plain text; required unless --body-html is set)"`
	BodyHTML         string   `name:"body-html" help:"Body (HTML; optional)"`
	ReplyToMessageID string   `name:"reply-to-message-id" help:"Reply to Gmail message ID (sets In-Reply-To/References and thread)"`
	ReplyTo          string   `name:"reply-to" help:"Reply-To header address"`
	Attach           []string `name:"attach" help:"Attachment file path (repeatable)"`
	From             string   `name:"from" help:"Send from this email address (must be a verified send-as alias)"`
	Track            bool     `name:"track" help:"Enable open tracking (requires tracking setup)"`
}
```

**Step 2: Add tracking logic to Run method**

In `internal/cmd/gmail_send.go`, before buildRFC822 call, add:

```go
	// Handle tracking
	var trackingID string
	htmlBody := c.BodyHTML
	if c.Track {
		trackingCfg, err := tracking.LoadConfig()
		if err != nil {
			return fmt.Errorf("load tracking config: %w", err)
		}
		if !trackingCfg.IsConfigured() {
			return fmt.Errorf("tracking not configured; run 'gog gmail track setup' first")
		}
		if strings.TrimSpace(htmlBody) == "" {
			return fmt.Errorf("--track requires --body-html (pixel must be in HTML)")
		}

		// Use first recipient for tracking
		firstRecipient := strings.Split(c.To, ",")[0]
		pixelURL, blob, err := tracking.GeneratePixelURL(trackingCfg, strings.TrimSpace(firstRecipient), c.Subject)
		if err != nil {
			return fmt.Errorf("generate tracking pixel: %w", err)
		}
		trackingID = blob

		// Inject pixel at end of HTML body
		pixelHTML := tracking.GeneratePixelHTML(pixelURL)
		htmlBody = htmlBody + pixelHTML
	}
```

**Step 3: Update buildRFC822 call to use htmlBody variable**

Change the buildRFC822 call to use `htmlBody` instead of `c.BodyHTML`.

**Step 4: Output tracking_id if tracking was used**

After sending, add:

```go
	if trackingID != "" {
		if outfmt.IsJSON(ctx) {
			// Include in JSON output
		} else {
			u.Out().Printf("tracking_id\t%s", trackingID)
		}
	}
```

**Step 5: Add import**

```go
import (
	"github.com/steipete/gogcli/internal/tracking"
)
```

**Step 6: Test manually**

```bash
go build -o gog ./cmd/gog
./gog gmail send --to test@example.com --subject "Test" --body-html "<p>Hello</p>" --track
```

Expected: Error "tracking not configured" (correct behavior)

**Step 7: Commit**

```bash
git add internal/cmd/gmail_send.go
git commit -m "feat(tracking): add --track flag to gmail send"
```

---

### Task 10: Implement gmail track Subcommands

**Files:**
- Create: `internal/cmd/gmail_track.go`
- Create: `internal/cmd/gmail_track_setup.go`
- Create: `internal/cmd/gmail_track_opens.go`
- Create: `internal/cmd/gmail_track_status.go`
- Modify: `internal/cmd/gmail.go`

**Step 1: Create gmail_track.go (subcommand group)**

```go
package cmd

// GmailTrackCmd groups tracking-related subcommands
type GmailTrackCmd struct {
	Setup  GmailTrackSetupCmd  `cmd:"" help:"Set up email tracking (deploy Cloudflare Worker)"`
	Opens  GmailTrackOpensCmd  `cmd:"" help:"Query email opens"`
	Status GmailTrackStatusCmd `cmd:"" help:"Show tracking configuration status"`
}
```

**Step 2: Create gmail_track_status.go**

```go
package cmd

import (
	"context"
	"fmt"

	"github.com/steipete/gogcli/internal/tracking"
	"github.com/steipete/gogcli/internal/ui"
)

type GmailTrackStatusCmd struct{}

func (c *GmailTrackStatusCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	cfg, err := tracking.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if !cfg.IsConfigured() {
		u.Out().Printf("Tracking: not configured")
		u.Out().Printf("")
		u.Out().Printf("Run 'gog gmail track setup' to enable email tracking.")
		return nil
	}

	u.Out().Printf("Tracking: enabled")
	u.Out().Printf("Tracker URL: %s", cfg.WorkerURL)

	return nil
}
```

**Step 3: Create gmail_track_opens.go**

```go
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/tracking"
	"github.com/steipete/gogcli/internal/ui"
)

type GmailTrackOpensCmd struct {
	TrackingID string `arg:"" optional:"" help:"Tracking ID from send command"`
	To         string `name:"to" help:"Filter by recipient email"`
	Since      string `name:"since" help:"Filter by time (e.g., '24h', '2024-01-01')"`
}

func (c *GmailTrackOpensCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	cfg, err := tracking.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !cfg.IsConfigured() {
		return fmt.Errorf("tracking not configured; run 'gog gmail track setup' first")
	}

	// Query by tracking ID
	if c.TrackingID != "" {
		return c.queryByTrackingID(ctx, cfg, u)
	}

	// Query via admin endpoint
	return c.queryAdmin(ctx, cfg, u, flags)
}

func (c *GmailTrackOpensCmd) queryByTrackingID(ctx context.Context, cfg *tracking.Config, u *ui.UI) error {
	reqURL := fmt.Sprintf("%s/q/%s", cfg.WorkerURL, c.TrackingID)

	resp, err := http.Get(reqURL)
	if err != nil {
		return fmt.Errorf("query tracker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("tracker returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Recipient      string `json:"recipient"`
		SentAt         string `json:"sent_at"`
		TotalOpens     int    `json:"total_opens"`
		HumanOpens     int    `json:"human_opens"`
		FirstHumanOpen *struct {
			At       string `json:"at"`
			Location *struct {
				City    string `json:"city"`
				Region  string `json:"region"`
				Country string `json:"country"`
			} `json:"location"`
		} `json:"first_human_open"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	u.Out().Printf("Recipient: %s", result.Recipient)
	u.Out().Printf("Sent: %s", result.SentAt)
	u.Out().Printf("Opens: %d total, %d human", result.TotalOpens, result.HumanOpens)

	if result.FirstHumanOpen != nil {
		loc := "unknown location"
		if result.FirstHumanOpen.Location != nil && result.FirstHumanOpen.Location.City != "" {
			loc = fmt.Sprintf("%s, %s", result.FirstHumanOpen.Location.City, result.FirstHumanOpen.Location.Region)
		}
		u.Out().Printf("First opened: %s · %s", result.FirstHumanOpen.At, loc)
	}

	return nil
}

func (c *GmailTrackOpensCmd) queryAdmin(ctx context.Context, cfg *tracking.Config, u *ui.UI, flags *RootFlags) error {
	reqURL, _ := url.Parse(cfg.WorkerURL + "/opens")
	q := reqURL.Query()
	if c.To != "" {
		q.Set("recipient", c.To)
	}
	if c.Since != "" {
		q.Set("since", c.Since)
	}
	reqURL.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	req.Header.Set("Authorization", "Bearer "+cfg.AdminKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("query tracker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("unauthorized: admin key may be incorrect")
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("tracker returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Opens []struct {
			Recipient   string `json:"recipient"`
			SubjectHash string `json:"subject_hash"`
			SentAt      string `json:"sent_at"`
			OpenedAt    string `json:"opened_at"`
			IsBot       bool   `json:"is_bot"`
			Location    *struct {
				City    string `json:"city"`
				Region  string `json:"region"`
				Country string `json:"country"`
			} `json:"location"`
		} `json:"opens"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(os.Stdout, result)
	}

	if len(result.Opens) == 0 {
		u.Out().Printf("No opens found")
		return nil
	}

	for _, o := range result.Opens {
		loc := ""
		if o.Location != nil && o.Location.City != "" {
			loc = fmt.Sprintf(" · %s, %s", o.Location.City, o.Location.Region)
		}
		botMark := ""
		if o.IsBot {
			botMark = " (bot)"
		}
		u.Out().Printf("%s  %s  %s%s%s", o.Recipient, o.SentAt[:10], o.OpenedAt, loc, botMark)
	}

	return nil
}
```

**Step 4: Create gmail_track_setup.go (placeholder)**

```go
package cmd

import (
	"context"
	"fmt"

	"github.com/steipete/gogcli/internal/ui"
)

type GmailTrackSetupCmd struct {
	Domain string `name:"domain" help:"Custom tracking domain (optional)"`
}

func (c *GmailTrackSetupCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	u.Out().Printf("Email Tracking Setup")
	u.Out().Printf("====================")
	u.Out().Printf("")
	u.Out().Printf("This feature requires wrangler CLI and a Cloudflare account.")
	u.Out().Printf("")
	u.Out().Printf("Setup steps:")
	u.Out().Printf("1. Install wrangler: npm install -g wrangler")
	u.Out().Printf("2. Login to Cloudflare: wrangler login")
	u.Out().Printf("3. Deploy the worker from internal/tracking/worker/")
	u.Out().Printf("")
	u.Out().Printf("Full automated setup coming soon.")

	return fmt.Errorf("automated setup not yet implemented")
}
```

**Step 5: Register Track command in gmail.go**

Add `Track GmailTrackCmd \`cmd:"" help:"Email open tracking"\`` to GmailCmd struct.

**Step 6: Commit**

```bash
git add internal/cmd/gmail_track*.go internal/cmd/gmail.go
git commit -m "feat(tracking): add gmail track subcommands"
```

---

## Phase 3: Testing & Polish

### Task 11: Integration Tests

**Files:**
- Create: `internal/tracking/integration_test.go`

**Step 1: Write integration test (skipped without config)**

```go
//go:build integration

package tracking

import (
	"testing"
)

func TestIntegrationEncryptDecryptWithWorker(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil || !cfg.IsConfigured() {
		t.Skip("Tracking not configured, skipping integration test")
	}

	// Generate a pixel URL
	pixelURL, blob, err := GeneratePixelURL(cfg, "integration-test@example.com", "Test Subject")
	if err != nil {
		t.Fatalf("GeneratePixelURL failed: %v", err)
	}

	t.Logf("Generated pixel URL: %s", pixelURL)
	t.Logf("Blob: %s", blob)

	// Verify we can decrypt locally
	payload, err := Decrypt(blob, cfg.TrackingKey)
	if err != nil {
		t.Fatalf("Local decrypt failed: %v", err)
	}

	if payload.Recipient != "integration-test@example.com" {
		t.Errorf("Recipient mismatch: %s", payload.Recipient)
	}
}
```

**Step 2: Commit**

```bash
git add internal/tracking/integration_test.go
git commit -m "test(tracking): add integration test"
```

---

### Task 12: Update Documentation

**Files:**
- Modify: `README.md`

**Step 1: Add tracking section to README**

Add section after existing gmail docs:

```markdown
### Email Tracking

Track when recipients open your emails:

```bash
# Set up tracking (one-time)
gog gmail track setup

# Send with tracking
gog gmail send --to recipient@example.com --subject "Hello" --body-html "<p>Hi!</p>" --track

# Check opens
gog gmail track opens <tracking_id>
gog gmail track opens --to recipient@example.com

# View status
gog gmail track status
```

**Note:** Tracking requires an HTML body (`--body-html`). The tracking pixel is automatically injected at the end of the email.
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add email tracking section to README"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1-5 | Cloudflare Worker + D1 schema |
| 2 | 6-10 | CLI integration (config, crypto, pixel, commands) |
| 3 | 11-12 | Integration tests + documentation |

**Total tasks:** 12
**Estimated time:** 2-3 hours with TDD approach
