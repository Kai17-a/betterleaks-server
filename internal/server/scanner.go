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

// Scanner scans content for secrets and exposes the loaded rules.
type Scanner interface {
	// Scan returns the findings in content. path is an optional virtual file
	// name used by path-based rules and allowlists.
	Scan(ctx context.Context, content, path string) ([]report.Finding, error)
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

// Scan is safe for concurrent use.
func (s *BetterleaksScanner) Scan(ctx context.Context, content, path string) ([]report.Finding, error) {
	fragment := sources.Fragment{Raw: content}
	if path != "" {
		fragment.SetAttr(sources.AttrPath, path)
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
