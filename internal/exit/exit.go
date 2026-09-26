// Package exit holds the exit codes of the home-kai admin CLI. They are a
// contract with the caller and mean the same across the kai CLI family
// (sec, yk-kai, ci-kai, figma-kai); the exact cause is in the --json envelope.
package exit

const (
	// OK — done.
	OK = 0

	// NotApplied — the service answered but there is no result: ping got no
	// replies, the agent service did not come up or go down, the network
	// lock is not initialized.
	NotApplied = 1

	// Tool — tool, arguments, settings or token: unknown command, bad flag,
	// no credentials, the coordinator rejected the token, wrong fingerprint.
	Tool = 2

	// NotFound — no such node, peer, policy, device or kai-agent service.
	NotFound = 3

	// Timeout — the coordinator did not answer in time.
	Timeout = 4
)
