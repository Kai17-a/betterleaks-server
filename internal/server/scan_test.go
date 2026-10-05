package server

import (
	"encoding/base64"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWindows(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		size, overlap int
		wantCount     int
	}{
		{"empty", "", 8, 2, 1},
		{"fits", "abcdefgh", 8, 2, 1},
		{"ascii", strings.Repeat("a", 20), 8, 2, 3},
		{"multibyte", strings.Repeat("あ", 20), 8, 2, 0},
		{"mixed", strings.Repeat("aあ🙂\n", 15), 9, 4, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wins := windows(tt.content, tt.size, tt.overlap)
			if tt.wantCount > 0 && len(wins) != tt.wantCount {
				t.Fatalf("got %d windows, want %d: %v", len(wins), tt.wantCount, wins)
			}
			if wins[0].start != 0 || wins[len(wins)-1].end != len(tt.content) {
				t.Fatalf("windows do not cover the content: %v", wins)
			}
			for i, w := range wins {
				if w.len() > tt.size {
					t.Errorf("window %d is %d bytes, limit %d", i, w.len(), tt.size)
				}
				if !utf8.ValidString(tt.content[w.start:w.end]) {
					t.Errorf("window %d splits a rune: %v", i, w)
				}
				if i == 0 {
					continue
				}
				prev := wins[i-1]
				if w.start <= prev.start || w.end <= prev.end {
					t.Errorf("window %d does not advance: %v after %v", i, w, prev)
				}
				if w.start > prev.end {
					t.Errorf("gap between window %d and %d: %v, %v", i-1, i, prev, w)
				}
			}
		})
	}
}

// scan posts content to a real handler and returns the decoded response.
func scan(t *testing.T, req scanRequest) scanResponse {
	t.Helper()
	rec := do(newRealHandler(t, Options{MaxBodyBytes: 8 << 20}), http.MethodPost, "/v1/scan", "application/json", scanBody(t, req))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %.200s", rec.Code, rec.Body.String())
	}
	return decode[scanResponse](t, rec)
}

// at returns the text a finding's position points at.
func at(content string, f Finding) string {
	starts := lineStarts(content)
	return content[starts[f.StartLine-1]+f.StartColumn-1 : starts[f.EndLine-1]+f.EndColumn]
}

func TestRedactedContent(t *testing.T) {
	password := "Xk9vQ2mLp7" + "Rt4Zs8"
	encoded := base64.StdEncoding.EncodeToString([]byte("token=" + testSecret))
	key := "-----BEGIN RSA PRIVATE KEY-----\n" +
		strings.Repeat("MIIEpAIBAAKCAQEA7x9Kd2LmQ7vRt4Yp8Zs1Wn6Bc3Hf5Jg0Aa2Eex9Kd2LmQ7vR\n", 6) +
		"-----END RSA PRIVATE KEY-----"

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			"token in japanese prose",
			"デプロイ時はトークン" + testSecret + "を使ってください。",
			"デプロイ時はトークン[REDACTED:github-pat]を使ってください。",
		},
		{
			"same token twice",
			testSecret + " and again " + testSecret,
			"[REDACTED:github-pat] and again [REDACTED:github-pat]",
		},
		{
			"whole uri, keeping the space after it",
			"接続先は postgres://svc_app:" + password + "@db.prod.acme-corp.io:5432/app です。",
			"接続先は [REDACTED:generic-credential-uri] です。",
		},
		{
			"secret repeated without its context",
			"postgres://svc_app:" + password + "@db.prod.acme-corp.io:5432/app\nつまり " + password + " が漏れています",
			"[REDACTED:generic-credential-uri]\nつまり [REDACTED:generic-credential-uri] が漏れています",
		},
		{
			"other credentials inside the match",
			"DATABASE_URL=https://deploy:" + password + "@git.acme-corp.io/repo?token=OTHER" + "SECRETVALUE123",
			"DATABASE_URL=[REDACTED:generic-credential-uri]",
		},
		{
			"base64 encoded token",
			"前の行\r\nデコードして: " + encoded + " 以上",
			"前の行\r\nデコードして: [REDACTED:github-pat] 以上",
		},
		{
			"multi-line private key",
			"前の行\n" + key + "\n後ろの行",
			"前の行\n[REDACTED:private-key]\n後ろの行",
		},
		{
			"component of a multi-part rule",
			"設定です。\nALGOLIA_APP_ID = \"Q3EGR7" + "XWJ5\"\nALGOLIA_API_KEY = \"k9v2m7r4z8x1w6b3" + "h5j0a2e9d4q7t1y8\"\n以上",
			"設定です。\n[REDACTED:algolia-application-id]\n[REDACTED:algolia-api-key]\n以上",
		},
		{
			"nothing to mask",
			"普通の文章です。\nfunc main() {}\n",
			"普通の文章です。\nfunc main() {}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := scan(t, scanRequest{Content: tt.content})
			if resp.RedactedContent != tt.want {
				t.Errorf("redacted_content =\n%q\nwant\n%q", resp.RedactedContent, tt.want)
			}
			if wantDetected := tt.want != tt.content; resp.Detected != wantDetected {
				t.Errorf("detected = %v, want %v", resp.Detected, wantDetected)
			}
			// The masked text must be clean when scanned again.
			if again := scan(t, scanRequest{Content: resp.RedactedContent}); again.Detected {
				t.Errorf("redacted content still has findings: %+v", again.Findings)
			}
		})
	}
}

// The scanned text is untrusted, so an allow comment in it must not suppress
// detection.
func TestAllowCommentIsIgnored(t *testing.T) {
	for _, marker := range []string{"gitleaks:allow", "betterleaks:allow"} {
		resp := scan(t, scanRequest{Content: "token = \"" + testSecret + "\" // " + marker})
		if !resp.Detected || strings.Contains(resp.RedactedContent, testSecret) {
			t.Errorf("%s suppressed detection: %q", marker, resp.RedactedContent)
		}
	}
}

func TestLocalSpan(t *testing.T) {
	text := "ab\ncdef\n\nSECRET\nxyz"
	starts := lineStarts(text)
	tests := []struct {
		name    string
		pos     position
		match   string
		decoded bool
		want    string
		ok      bool
	}{
		{"single line", position{2, 2, 2, 3}, "de", false, "de", true},
		{"multi line", position{1, 2, 2, 2}, "b\ncd", false, "b\ncd", true},
		{"ends right after a line break", position{2, 3, 3, 0}, "ef\n", false, "ef\n", true},
		// The library trims leading line breaks from the match but keeps the
		// untrimmed start, so the range is shifted left of the match.
		{"leading line break trimmed", position{2, 5, 3, 5}, "SECRET", false, "SECRET", true},
		{"decoded range is taken as is", position{2, 1, 2, 4}, "not in text", true, "cdef", true},
		{"line zero", position{0, 0, 0, 0}, "", false, "", false},
		{"line out of range", position{9, 1, 9, 2}, "x", false, "", false},
		{"past the end", position{5, 1, 5, 9}, "x", false, "", false},
		{"empty", position{2, 2, 2, 1}, "", false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := localSpan(text, starts, tt.pos, tt.match, tt.decoded)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && text[got.start:got.end] != tt.want {
				t.Fatalf("span = %q, want %q", text[got.start:got.end], tt.want)
			}
		})
	}
}

// redact:false exposes secrets in the findings but never in redacted_content.
func TestRedactedContentWithUnredactedFindings(t *testing.T) {
	content := "token = \"" + testSecret + "\""
	resp := scan(t, scanRequest{Content: content, Redact: ptr(false)})
	if len(resp.Findings) != 1 || resp.Findings[0].Secret != testSecret {
		t.Fatalf("findings = %+v", resp.Findings)
	}
	if strings.Contains(resp.RedactedContent, testSecret) {
		t.Fatalf("redacted_content contains the secret: %q", resp.RedactedContent)
	}
}

func TestRedactIsDefault(t *testing.T) {
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json",
		`{"content":"token = \"`+testSecret+`\""}`)
	if strings.Contains(rec.Body.String(), testSecret) {
		t.Fatalf("response contains the secret without redact:false: %s", rec.Body.String())
	}
}

// A long line is scanned in windows; a secret must be found exactly once and
// at the right position wherever it falls relative to a window boundary.
func TestSecretAcrossWindowBoundary(t *testing.T) {
	const boundary = scanWindowBytes
	filler := strings.Repeat("x ", scanWindowBytes) // one line, no newline
	for _, before := range []int{-len(testSecret) - 1, -len(testSecret), -39, -20, -1, 0, 1, 2} {
		start := boundary + before
		content := filler[:start] + testSecret + " " + filler[:scanWindowBytes]
		resp := scan(t, scanRequest{Content: content, Redact: ptr(false)})
		if len(resp.Findings) != 1 {
			t.Errorf("offset %+d: %d findings, want 1: %+v", before, len(resp.Findings), resp.Findings)
			continue
		}
		f := resp.Findings[0]
		if f.StartLine != 1 || f.StartColumn != start+1 || at(content, f) != testSecret {
			t.Errorf("offset %+d: finding at %d:%d-%d, want column %d", before, f.StartLine, f.StartColumn, f.EndColumn, start+1)
		}
		if want := content[:start] + "[REDACTED:github-pat]" + content[start+len(testSecret):]; resp.RedactedContent != want {
			t.Errorf("offset %+d: redacted_content is wrong around the secret", before)
		}
	}
}

// A long multi-line, multibyte content: line and column must be relative to
// the whole content, not to the window a secret was found in.
func TestPositionsInLargeContent(t *testing.T) {
	line := strings.Repeat("これは長い段落です。", 40) // 1,200 bytes
	var b strings.Builder
	wantLines := map[int]bool{}
	for i := 1; i <= 400; i++ {
		if i%37 == 0 {
			b.WriteString("メモ: トークンは " + testSecret + " です\n")
			wantLines[i] = true
			continue
		}
		b.WriteString(line + "\n")
	}
	content := b.String()
	if len(content) < 4*scanWindowBytes {
		t.Fatalf("content is only %d bytes", len(content))
	}

	resp := scan(t, scanRequest{Content: content, Redact: ptr(false)})
	if len(resp.Findings) != len(wantLines) {
		t.Fatalf("%d findings, want %d", len(resp.Findings), len(wantLines))
	}
	for _, f := range resp.Findings {
		if !wantLines[f.StartLine] {
			t.Errorf("unexpected finding on line %d", f.StartLine)
		}
		if at(content, f) != testSecret {
			t.Errorf("line %d: position does not point at the secret", f.StartLine)
		}
	}
	if strings.Contains(resp.RedactedContent, testSecret) {
		t.Error("redacted_content contains the secret")
	}
	if want := strings.ReplaceAll(content, testSecret, "[REDACTED:github-pat]"); resp.RedactedContent != want {
		t.Error("redacted_content differs from the content with secrets replaced")
	}
}

// Long lines used to be rejected; they are now scanned.
func TestLongLineIsAccepted(t *testing.T) {
	content := strings.Repeat("これは長い段落です。", 5000) + testSecret + strings.Repeat("。続き", 5000)
	resp := scan(t, scanRequest{Content: content})
	if resp.Count != 1 || strings.Contains(resp.RedactedContent, testSecret) {
		t.Fatalf("count = %d", resp.Count)
	}
}

// Secrets at random offsets in content of mixed line lengths: every one must
// be reported once, at the right position, and masked.
func TestRandomPlacement(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	pieces := []string{"これは文章です。", "plain words here ", "x", "\n", "\r\n", "🙂", "{\"k\":\"v\"},", strings.Repeat("長い行", 300)}
	for round := range 5 {
		var b strings.Builder
		var offsets []int
		for b.Len() < 300<<10 {
			if rng.IntN(60) == 0 {
				b.WriteString(" ")
				offsets = append(offsets, b.Len())
				b.WriteString(testSecret)
				b.WriteString(" ")
				continue
			}
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		content := b.String()

		resp := scan(t, scanRequest{Content: content, Redact: ptr(false)})
		if len(resp.Findings) != len(offsets) {
			t.Fatalf("round %d: %d findings, want %d", round, len(resp.Findings), len(offsets))
		}
		starts := lineStarts(content)
		for i, f := range resp.Findings {
			if got := starts[f.StartLine-1] + f.StartColumn - 1; got != offsets[i] || at(content, f) != testSecret {
				t.Fatalf("round %d: finding %d at offset %d, want %d", round, i, got, offsets[i])
			}
		}
		if want := strings.ReplaceAll(content, testSecret, "[REDACTED:github-pat]"); resp.RedactedContent != want {
			t.Fatalf("round %d: redacted_content differs from the content with secrets replaced", round)
		}
	}
}

func TestLiteralsFind(t *testing.T) {
	lit := newLiterals(map[string]string{
		"abcdefgh":     "r1",
		"efghijkl":     "r2", // overlaps r1 from a later start
		"abcdefghXYZW": "r3", // r1 is its prefix
		"short":        "r4", // below the length limit
	})
	tests := map[string]string{
		"abcdefghijkl":         "REDACTED",
		"<abcdefgh>":           "<REDACTED>",
		"abcdefghXYZW tail":    "REDACTED tail",
		"x abcdefghXY efghijk": "x REDACTEDXY efghijk",
		"short stays":          "short stays",
		"":                     "",
	}
	for in, want := range tests {
		if got := lit.redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
	if got := (*literals)(nil).redact("abcdefgh"); got != "abcdefgh" {
		t.Errorf("nil literals changed the text: %q", got)
	}
}

// A window can report the same finding as an earlier one but with more
// components; those must still be masked.
func TestComponentFoundOnlyInLaterWindow(t *testing.T) {
	content := []byte(strings.Repeat(" ", 80000))
	firstID, secondID := "Q3EGR7"+"XWJ5", "R4FHS8"+"YZK6"
	copy(content[45000:], `ALGOLIA_APP_ID = "`+firstID+`"`)
	copy(content[50000:], `ALGOLIA_API_KEY = "k9v2m7r4z8x1w6b3`+`h5j0a2e9d4q7t1y8"`)
	copy(content[70000:], `ALGOLIA_APP_ID = "`+secondID+`"`)

	resp := scan(t, scanRequest{Content: string(content)})
	for _, id := range []string{firstID, secondID} {
		if strings.Contains(resp.RedactedContent, id) {
			t.Errorf("component %s is not masked", id)
		}
	}
}

// A secret that is a prefix of another must not leave the rest of the longer
// one behind where it is quoted on its own.
func TestLiteralMaskingOfPrefixSecrets(t *testing.T) {
	short, long := "Xk9vQ2mL", "Xk9vQ2mL"+"p7Rt4Zs8"
	content := "postgres://svc:" + short + "@db.prod.acme-corp.io/app\n" +
		"postgres://svc:" + long + "@db.prod.acme-corp.io/app\n" +
		"copied value: " + long
	resp := scan(t, scanRequest{Content: content})
	if resp.Count != 2 {
		t.Fatalf("count = %d, want 2", resp.Count)
	}
	if want := "[REDACTED:generic-credential-uri]\n[REDACTED:generic-credential-uri]\ncopied value: [REDACTED:generic-credential-uri]"; resp.RedactedContent != want {
		t.Errorf("redacted_content = %q, want %q", resp.RedactedContent, want)
	}
}

// A secret that is part of a rule name must not come back through the
// placeholder, and placeholders must not be masked again.
func TestSecretInsidePlaceholderLabel(t *testing.T) {
	resp := scan(t, scanRequest{Content: "postgres://svc:credential@db.prod.acme-corp.io/app"})
	if !resp.Detected {
		t.Skip("rule no longer reports this password")
	}
	if resp.RedactedContent != "[REDACTED]" {
		t.Errorf("redacted_content = %q, want [REDACTED]", resp.RedactedContent)
	}
}

// With redaction on, the echoed path must not expose any detected secret, not
// only the secret of the finding it is attached to.
func TestRedactMasksEverySecretInPath(t *testing.T) {
	first, second := "Xk9vQ2mL"+"p7Rt4Zs8", "Nz6aT3bV"+"r8Ys5Hm2"
	body := scanBody(t, scanRequest{
		Content: "postgres://svc:" + first + "@db.prod.acme-corp.io/app\npostgres://svc:" + second + "@db.prod.acme-corp.io/app",
		Path:    "credentials/" + first + ".env",
	})
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json", body)
	if resp := decode[scanResponse](t, rec); resp.Count != 2 {
		t.Fatalf("count = %d, want 2 (body %s)", resp.Count, rec.Body.String())
	}
	for _, secret := range []string{first, second} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("response contains a detected secret: %s", rec.Body.String())
		}
	}
}
