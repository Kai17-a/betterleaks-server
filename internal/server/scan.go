package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/report"
	"github.com/rrethy/ahocorasick"
)

// Content is scanned in overlapping byte windows rather than as one fragment.
// The library's cost is quadratic in the findings of a fragment and it clones
// the whole containing line per finding, so bounding the fragment bounds both,
// whatever the line lengths. The overlap is what keeps a secret that straddles
// a cut detectable: anything up to scanOverlapBytes long lies entirely inside
// at least one window. That has to cover a match together with the context
// its rule looks at (up to 8 KiB on either side for generic-password).
const (
	scanWindowBytes  = 64 << 10
	scanOverlapBytes = 32 << 10
)

// minLiteralSecretBytes is the shortest secret that is also masked wherever
// else it literally occurs. Shorter values are too likely to be ordinary text.
const minLiteralSecretBytes = 8

const confidenceAttr = "confidence"

// span is a half-open byte range [start, end) of the scanned content.
type span struct{ start, end int }

func (s span) len() int { return s.end - s.start }

// mask is a part of the content to replace with a rule's placeholder.
type mask struct {
	span
	rule string
}

// detection is a finding located in the whole content rather than in the
// window it was found in.
type detection struct {
	finding report.Finding
	// match is where the finding sits in the content. It is the zero span for
	// findings without a position (path-only rules).
	match span
}

// scanResult is what a scan of a whole content found. What to report and what
// to mask are kept apart on purpose: reporting drops duplicates and leftovers
// of the windowing, masking must not lose anything any window saw.
type scanResult struct {
	// detections are the findings to report, ordered by position.
	detections []detection
	// masks are the matches of every finding and component in every window.
	masks []mask
	// secrets maps each secret value of a finding or component to the rule
	// that found it first.
	secrets map[string]string
}

func (d detection) positioned() bool { return d.match.len() > 0 }

// windows returns the scan windows covering content, cut on rune boundaries.
func windows(content string, size, overlap int) []span {
	n := len(content)
	if n <= size {
		return []span{{0, n}}
	}
	var out []span
	start := 0
	for {
		end := runeStart(content, min(start+size, n))
		if end <= start {
			// Only possible with invalid UTF-8; fall back to a byte cut.
			end = min(start+size, n)
		}
		out = append(out, span{start, end})
		if end == n {
			return out
		}
		next := runeStart(content, end-overlap)
		if next <= start {
			next = end
		}
		start = next
	}
}

// runeStart moves i back to the start of the rune it points into.
func runeStart(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// lineStarts returns the byte offset at which each line of s begins.
func lineStarts(s string) []int {
	starts := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// position is where the library says a match is: 1-based lines, 1-based byte
// start column, and an end column that is the exclusive byte offset within the
// end line (0 when the match ends right after a line break).
type position struct{ startLine, startColumn, endLine, endColumn int }

// localSpan converts a library position into a byte range of the fragment
// text. decoded matches are not literally in the text, so only their range is
// used; for the others the range is checked against the match, because the
// library trims leading line breaks off a match without moving its start.
func localSpan(text string, starts []int, p position, match string, decoded bool) (span, bool) {
	if p.startLine < 1 || p.endLine < p.startLine || p.endLine > len(starts) || p.startColumn < 1 || p.endColumn < 0 {
		return span{}, false
	}
	s := span{starts[p.startLine-1] + p.startColumn - 1, starts[p.endLine-1] + p.endColumn}
	if s.start >= s.end || s.end > len(text) {
		return span{}, false
	}
	if decoded || match == "" || text[s.start:s.end] == match {
		return s, true
	}
	from := max(0, s.start-len(match))
	to := min(len(text), s.end+len(match))
	if i := strings.Index(text[from:to], match); i >= 0 {
		return span{from + i, from + i + len(match)}, true
	}
	return s, true
}

func isDecoded(tags []string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, "decoded:") {
			return true
		}
	}
	return false
}

// scanContent scans content window by window.
func scanContent(ctx context.Context, sc Scanner, content, path string) (scanResult, error) {
	wins := windows(content, scanWindowBytes, scanOverlapBytes)
	res := scanResult{secrets: make(map[string]string)}
	seen := make(map[string]struct{})

	for i, w := range wins {
		if err := ctx.Err(); err != nil {
			return scanResult{}, err
		}
		text := content[w.start:w.end]
		found, err := sc.ScanFragment(ctx, text, path, i == 0)
		if err != nil {
			return scanResult{}, err
		}
		if len(found) == 0 {
			continue
		}

		starts := lineStarts(text)
		for _, f := range found {
			decoded := isDecoded(f.Tags)
			var d detection
			cut := false
			pos := position{f.StartLine, f.StartColumn, f.EndLine, f.EndColumn}
			if local, ok := localSpan(text, starts, pos, f.Match, decoded); ok {
				d.match = span{w.start + local.start, w.start + local.end}
				res.masks = append(res.masks, mask{d.match, f.RuleID})
				cut = cutShort(local, len(text), i == 0, i == len(wins)-1)
			}
			// A match cut short by a window edge is masked but its secret is
			// only a fragment of the real one, which a neighbour reports.
			if !cut {
				res.addSecret(f.Secret, f.RuleID)
			}
			// Multi-part rules report the parts they combined; each part is
			// a credential in its own right.
			for _, set := range f.ComponentSets {
				for _, c := range set.Components {
					res.addSecret(c.Secret, c.RuleID)
					pos := position{c.StartLine, c.StartColumn, c.EndLine, c.EndColumn}
					if local, ok := localSpan(text, starts, pos, c.Match, decoded); ok {
						res.masks = append(res.masks, mask{span{w.start + local.start, w.start + local.end}, c.RuleID})
					}
				}
			}
			if cut {
				continue
			}

			key := fmt.Sprintf("%s\x00%d\x00%d\x00%s", f.RuleID, d.match.start, d.match.end, f.Secret)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			// Drop everything that keeps the window and its lines alive.
			f.Line = ""
			f.Fragment = nil
			f.MatchContext = ""
			f.CaptureGroups = nil
			f.ComponentSets = nil
			d.finding = f
			res.detections = append(res.detections, d)
		}
	}

	res.detections = dropContained(res.detections)
	relocate(res.detections, content, path)
	return res, nil
}

func (r *scanResult) addSecret(secret, ruleID string) {
	if secret == "" {
		return
	}
	if _, ok := r.secrets[secret]; !ok {
		r.secrets[secret] = ruleID
	}
}

// cutShort reports whether a match touches a window edge that is a cut rather
// than the real start or end of the content, and is short enough that the
// neighbouring window holds the same text away from its own edges. Such a
// match may be a truncated secret; the neighbour reports the complete one.
func cutShort(local span, textLen int, first, last bool) bool {
	if local.len() >= scanOverlapBytes {
		return false
	}
	return (!last && local.end == textLen) || (!first && local.start == 0)
}

// dropContained sorts detections by position and removes those of a rule that
// lie strictly inside another detection of the same rule: leftovers of a
// secret that a window boundary cut in two.
func dropContained(dets []detection) []detection {
	sort.SliceStable(dets, func(i, j int) bool {
		a, b := dets[i].match, dets[j].match
		if a.start != b.start {
			return a.start < b.start
		}
		return a.end > b.end
	})

	widest := make(map[string]span)
	kept := dets[:0]
	for _, d := range dets {
		if d.positioned() {
			if w, ok := widest[d.finding.RuleID]; ok && d.match.end <= w.end && d.match != w {
				continue
			}
			if w, ok := widest[d.finding.RuleID]; !ok || d.match.end > w.end {
				widest[d.finding.RuleID] = d.match
			}
		}
		kept = append(kept, d)
	}
	return kept
}

// relocate rewrites line, column and fingerprint from window-relative to
// content-relative values.
func relocate(dets []detection, content, path string) {
	var starts []int
	for i := range dets {
		d := &dets[i]
		if !d.positioned() {
			continue
		}
		if starts == nil {
			starts = lineStarts(content)
		}
		last := d.match.end - 1
		startLine := sort.SearchInts(starts, d.match.start+1) - 1
		endLine := sort.SearchInts(starts, last+1) - 1

		f := &d.finding
		f.StartLine = startLine + 1
		f.StartColumn = d.match.start - starts[startLine] + 1
		f.EndLine = endLine + 1
		f.EndColumn = last - starts[endLine] + 1
		f.Fingerprint = fmt.Sprintf("%s:%s:%d", path, f.RuleID, f.StartLine)
	}
}

// literals finds the detected secrets wherever they occur verbatim.
type literals struct {
	matcher *ahocorasick.Matcher
	rules   map[string]string
}

// newLiterals returns nil if no secret is long enough to search for.
func newLiterals(secrets map[string]string) *literals {
	var words []string
	for secret := range secrets {
		if len(secret) >= minLiteralSecretBytes {
			words = append(words, secret)
		}
	}
	if len(words) == 0 {
		return nil
	}
	sort.Strings(words)
	return &literals{matcher: ahocorasick.CompileStrings(words), rules: secrets}
}

// find returns every occurrence of every secret in text, overlapping ones
// included.
func (l *literals) find(text string) []mask {
	if l == nil {
		return nil
	}
	var out []mask
	for _, m := range l.matcher.FindAllString(text) {
		out = append(out, mask{span{m.Index, m.Index + len(m.Word)}, l.rules[string(m.Word)]})
	}
	return out
}

// redact replaces every occurrence of a secret in text with "REDACTED".
func (l *literals) redact(text string) string {
	return applyMasks(text, l.find(text), func(string) string { return redacted })
}

// redactContent returns content with every match replaced by
// "[REDACTED:<rule id>]". The whole match is replaced, not only the secret in
// it: a match can span more than one credential (e.g. a connection URI with a
// password and a token), and an encoded secret does not occur literally.
// Secrets are also masked wherever else they occur verbatim, because the
// library reports a secret only where a rule matched its surroundings.
func redactContent(content string, res scanResult, lit *literals) string {
	masks := make([]mask, 0, len(res.masks))
	for _, m := range res.masks {
		// Rules may match a trailing delimiter; keep the surrounding
		// whitespace out of the placeholder.
		for m.end > m.start && isSpace(content[m.end-1]) {
			m.end--
		}
		for m.start < m.end && isSpace(content[m.start]) {
			m.start++
		}
		if m.len() > 0 {
			masks = append(masks, m)
		}
	}
	masks = append(masks, lit.find(content)...)

	labels := make(map[string]string)
	return applyMasks(content, masks, func(ruleID string) string {
		label, ok := labels[ruleID]
		if !ok {
			label = "[" + redacted + ":" + ruleID + "]"
			// A secret that happens to be part of the rule name must not
			// reappear through the placeholder.
			if len(lit.find(label)) > 0 {
				label = "[" + redacted + "]"
			}
			labels[ruleID] = label
		}
		return label
	})
}

// applyMasks returns text with the masked ranges replaced. Overlapping masks
// become one replacement, named after the earliest and widest of them.
func applyMasks(text string, masks []mask, label func(ruleID string) string) string {
	if len(masks) == 0 {
		return text
	}
	sort.SliceStable(masks, func(i, j int) bool {
		if masks[i].start != masks[j].start {
			return masks[i].start < masks[j].start
		}
		return masks[i].end > masks[j].end
	})

	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for i := 0; i < len(masks); {
		m := masks[i]
		for i++; i < len(masks) && masks[i].start < m.end; i++ {
			m.end = max(m.end, masks[i].end)
		}
		b.WriteString(text[pos:m.start])
		b.WriteString(label(m.rule))
		pos = m.end
	}
	b.WriteString(text[pos:])
	return b.String()
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
