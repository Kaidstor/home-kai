// Package output prints home-kai results: text for a human by default, the
// kai CLI family JSON envelope with --json.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// SchemaVersion grows when the shape of the envelope or of data changes.
const SchemaVersion = 1

// Failure is an error in machine form; callers branch on Kind, not on text.
type Failure struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Envelope is what --json prints. Exit duplicates the process exit code: an
// agent that ran the command in the background reads a file where the code
// is already gone.
type Envelope struct {
	V       int      `json:"v"`
	Command string   `json:"command"`
	Exit    int      `json:"exit"`
	Data    any      `json:"data"`
	Warning []string `json:"warning,omitempty"`
	Error   *Failure `json:"error"`
}

type Printer struct {
	JSON bool
	Out  io.Writer
	Err  io.Writer

	warnings []string
}

func New(jsonMode bool) *Printer {
	return &Printer{JSON: jsonMode, Out: os.Stdout, Err: os.Stderr}
}

// Warn collects a warning: the --json envelope carries it in warning, text
// mode prints it to stderr before the result. It never changes the exit code.
func (p *Printer) Warn(format string, a ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, a...))
}

// Result prints the result and returns the exit code, so a command ends with
// `return p.Result(...)`. Text mode calls human instead of printing data.
func (p *Printer) Result(command string, code int, data any, human func(io.Writer)) int {
	if !p.JSON {
		p.flushWarnings()
		if human != nil {
			human(p.Out)
		}
		return code
	}
	p.encode(Envelope{
		V:       SchemaVersion,
		Command: command,
		Exit:    code,
		Data:    data,
		Warning: p.warnings,
	})
	return code
}

// Fail prints an error and returns the exit code: text mode to stderr, --json
// as the same envelope on stdout, so the caller reads one stream to learn the
// outcome.
func (p *Printer) Fail(command string, code int, kind, format string, a ...any) int {
	msg := fmt.Sprintf(format, a...)
	if !p.JSON {
		p.flushWarnings()
		fmt.Fprintln(p.Err, "home-kai:", msg)
		return code
	}
	p.encode(Envelope{
		V:       SchemaVersion,
		Command: command,
		Exit:    code,
		Warning: p.warnings,
		Error:   &Failure{Kind: kind, Message: msg},
	})
	return code
}

func (p *Printer) flushWarnings() {
	for _, w := range p.warnings {
		fmt.Fprintln(p.Err, "warn:", w)
	}
	p.warnings = nil
}

func (p *Printer) encode(e Envelope) {
	enc := json.NewEncoder(p.Out)
	enc.SetIndent("", "  ")
	// Without this `&` in URLs and join commands turns into &.
	enc.SetEscapeHTML(false)
	_ = enc.Encode(e)
}
