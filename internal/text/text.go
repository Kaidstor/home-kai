// Package text holds the small string helpers shared by the coordinator, the
// store and the CLIs: comma-list (de)serialization and DNS-label slugging.
// Keeping them in one place stops the same three loops from being re-inlined
// under four different names.
package text

import "strings"

// JoinCSV serializes a string list into one comma-separated field. Entries are
// expected to be comma-free (validated CIDRs, slugged tags).
func JoinCSV(items []string) string { return strings.Join(items, ",") }

// JoinOr joins items with commas, or returns the empty placeholder when the
// list is empty — for rendering tag sets ("any"/"*") in logs and tables.
func JoinOr(items []string, empty string) string {
	if len(items) == 0 {
		return empty
	}
	return strings.Join(items, ",")
}

// SplitCSV is the inverse of JoinCSV: it splits a stored field verbatim (no
// trimming) and returns nil for the empty string.
func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// Fields parses a user-supplied comma list, trimming spaces around each item
// and dropping empties — for CLI flags like `--tags a, b ,` .
func Fields(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Slug reduces s to a DNS-safe label: lowercase, only [a-z0-9], every other
// run collapsed to a single '-', with leading/trailing dashes stripped.
// Returns "" when nothing survives (callers pick their own fallback).
func Slug(s string) string {
	var b []byte
	dash := true // swallow leading separators
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b = append(b, byte(r))
			dash = false
		default:
			if !dash {
				b = append(b, '-')
				dash = true
			}
		}
	}
	return strings.Trim(string(b), "-")
}
