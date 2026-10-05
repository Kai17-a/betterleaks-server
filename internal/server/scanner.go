package server

import (
	"context"
	"fmt"
	"sort"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// defaultMaxDecodeDepth mirrors the betterleaks CLI default for --max-decode-depth.
const defaultMaxDecodeDepth = 5

// Scanner scans text for secrets and exposes the loaded rules.
type Scanner interface {
	// ScanFragment returns the findings in one fragment of a content. path is
	// an optional virtual file name used by path-based rules and allowlists.
	// first reports whether this is the first fragment of the content.
	ScanFragment(ctx context.Context, text, path string, first bool) ([]report.Finding, error)
	Rules() []Rule
}

// BetterleaksScanner is a Scanner backed by a betterleaks detector using the
// default configuration. Secret validation (outbound HTTP) is never enabled.
type BetterleaksScanner struct {
	detector *detect.Detector
	rules    []Rule
}

// NewBetterleaksScanner builds a scanner from the betterleaks default config.
func NewBetterleaksScanner(ctx context.Context) (*BetterleaksScanner, error) {
	cfg, err := config.Default()
	if err != nil {
		return nil, fmt.Errorf("load default config: %w", err)
	}

	d := detect.NewDetectorContext(ctx, cfg, detect.ValidationOptions{})
	d.MaxDecodeDepth = defaultMaxDecodeDepth
	// The scanned text is untrusted: a "betterleaks:allow" comment in it must
	// not be able to switch detection off.
	d.IgnoreGitleaksAllow = true

	rules := make([]Rule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		tags := r.Tags
		if tags == nil {
			tags = []string{}
		}
		rules = append(rules, Rule{ID: r.RuleID, Description: r.Description, Tags: tags})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	return &BetterleaksScanner{detector: d, rules: rules}, nil
}

// ScanFragment is safe for concurrent use.
func (s *BetterleaksScanner) ScanFragment(ctx context.Context, text, path string, first bool) ([]report.Finding, error) {
	fragment := sources.Fragment{Raw: text}
	if path != "" {
		fragment.SetAttr(sources.AttrPath, path)
		if !first {
			// Rules that match on the path alone must report once per
			// content, not once per fragment.
			fragment.SetAttr(sources.AttrFSFirstFragment, "false")
		}
	}

	// DetectContext is used instead of Run: Run mutates detector-level state
	// (ValidationCounts, the legacy findings slice) without locking, so it
	// cannot be shared across concurrent requests. DetectContext only touches
	// state the detector already guards for concurrent scans.
	findings := s.detector.DetectContext(ctx, fragment)
	if err := ctx.Err(); err != nil {
		// The scan loop stops early on cancellation, so the result is partial.
		return nil, err
	}
	return findings, nil
}

func (s *BetterleaksScanner) Rules() []Rule {
	return s.rules
}
