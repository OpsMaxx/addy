package services

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// List prints every wizard with its cost.
//
// The cost is printed in the LIST, not only in the detail view, because the
// list is where somebody decides what to look at -- and a cost discovered after
// deciding is a cost discovered too late to affect the decision.
func List(out io.Writer) {
	fmt.Fprintln(out, "Services addy can deploy beside itself.")
	fmt.Fprintln(out, "All are off until you install one. Each one costs something; the cost is below.")
	fmt.Fprintln(out)
	for _, s := range All() {
		fmt.Fprintf(out, "  %-12s %s\n", s.ID, s.Name)
		fmt.Fprintf(out, "               %s\n", s.Summary)
		for _, line := range wrap(s.Cost, 72) {
			fmt.Fprintf(out, "               %s\n", line)
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, "`addy service show <id>` for what it asks for.")
	fmt.Fprintln(out, "`addy service check <id>` runs its prerequisites without writing anything.")
}

// Show prints one wizard's questions.
func Show(out io.Writer, id string) error {
	s, err := Find(id)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n\n%s\n\n", s.Name, s.Summary)
	fmt.Fprintln(out, "WHAT IT COSTS")
	for _, line := range wrap(s.Cost, 74) {
		fmt.Fprintf(out, "  %s\n", line)
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "WHAT IT ASKS FOR")
	for _, f := range s.Fields {
		req := ""
		if f.Required {
			req = "  (required)"
		}
		fmt.Fprintf(out, "  %-18s %s%s\n", f.Key, f.Label, req)
		if f.Default != "" {
			fmt.Fprintf(out, "  %-18s default: %s\n", "", f.Default)
		}
		for _, line := range wrap(f.Help, 56) {
			fmt.Fprintf(out, "  %-18s %s\n", "", line)
		}
	}
	if len(s.Ports) > 0 {
		fmt.Fprintf(out, "\nPORTS IT NEEDS  %s\n", joinInts(s.Ports))
	}
	return nil
}

// Report prints the result of every prerequisite.
func Report(out io.Writer, s Service, results []CheckResult) {
	fmt.Fprintf(out, "%s\n\n", s.Name)
	for _, r := range results {
		mark := "  ok  "
		if !r.OK {
			mark = " FAIL "
			if !r.Fatal {
				mark = " note "
			}
		}
		fmt.Fprintf(out, "%s %s\n", mark, r.Name)
		for _, line := range wrap(r.Why, 68) {
			fmt.Fprintf(out, "       %s\n", line)
		}
	}
	fmt.Fprintln(out)
	if Blocking(results) {
		fmt.Fprintln(out, "Not ready. Nothing has been written.")
		return
	}
	fmt.Fprintln(out, "Ready. `addy service install "+s.ID+"` writes the deployment.")
}

// Install renders the deployment after checking, and says exactly what it
// wrote.
//
// An operator handed a working service and no idea what changed on their box
// has been given a black box, and the next thing they do is distrust it.
func Install(out io.Writer, s Service, cfg Config) error {
	results := Check(s, cfg)
	Report(out, s, results)
	if Blocking(results) {
		return fmt.Errorf("%s is not ready to install", s.ID)
	}

	// The socket proxy, once, the first time any service is installed.
	dir := filepath.Join(cfg.DeployDir, "services")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	proxy := filepath.Join(dir, "docker-proxy.yml")
	if _, err := os.Stat(proxy); os.IsNotExist(err) {
		if err := os.WriteFile(proxy, []byte(SocketProxyCompose), 0o640); err != nil {
			return err
		}
		fmt.Fprintf(out, "\n  wrote %s\n", proxy)
	}

	written, err := Render(s, cfg)
	if err != nil {
		return err
	}
	for _, p := range written {
		fmt.Fprintf(out, "  wrote %s\n", p)
	}
	fmt.Fprintf(out, `
Nothing is running yet. Read what was written, then:

    docker compose -f %s up -d

`, filepath.Join(dir, s.ID+".yml"))
	return nil
}

func joinInts(ns []int) string {
	sorted := append([]int(nil), ns...)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, n := range sorted {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ", ")
}

// wrap breaks text at a width, for a terminal. Naive on purpose: the inputs
// are this package's own prose and a word longer than the width is a URL,
// which should not be broken anyway.
func wrap(text string, width int) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	words := strings.Fields(text)
	var lines []string
	line := ""
	for _, w := range words {
		if line == "" {
			line = w
			continue
		}
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
