// prodready — a fast, zero-dependency pre-flight check for Kubernetes manifests
// and Dockerfiles. It flags the production anti-patterns that show up in most
// un-reviewed setups: :latest images, root containers, missing limits and
// probes, plaintext secrets, mounted docker sockets, and more.
//
// It is heuristic and intentionally fast — a pre-commit / CI gate, not a
// replacement for deep scanners like kube-score or checkov. Pair it with those.
//
// Usage:
//   prodready [paths...]        # defaults to "."
//   prodready --format json .
//   prodready --min high .      # only fail on HIGH findings
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var version = "dev"

func main() {
	format := flag.String("format", "text", "output format: text|json")
	minSev := flag.String("min", "low", "minimum severity to report/fail on: low|medium|high")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("prodready", version)
		return
	}

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	threshold := parseSeverity(*minSev)

	var findings []Finding
	for _, p := range paths {
		findings = append(findings, scanPath(p)...)
	}

	// filter by threshold
	kept := findings[:0]
	for _, f := range findings {
		if f.Severity >= threshold {
			kept = append(kept, f)
		}
	}
	findings = kept

	// sort: severity desc, then file, then rule
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Rule < findings[j].Rule
	})

	if *format == "json" {
		printJSON(findings)
	} else {
		printText(findings)
	}

	// exit non-zero if any HIGH finding survived the threshold — makes it a CI gate
	for _, f := range findings {
		if f.Severity == High {
			os.Exit(1)
		}
	}
}

func scanPath(root string) []Finding {
	var out []Finding
	info, err := os.Stat(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prodready: cannot read", root+":", err)
		return out
	}
	if !info.IsDir() {
		return scanFile(root)
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		out = append(out, scanFile(path)...)
		return nil
	})
	return out
}

func scanFile(path string) []Finding {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))
	isYAML := ext == ".yaml" || ext == ".yml"
	isDocker := base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || ext == ".dockerfile"
	if !isYAML && !isDocker {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if isDocker {
		return LintDockerfile(path, string(b))
	}
	return LintYAML(path, string(b))
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".terraform":
		return true
	}
	return false
}

func parseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "high":
		return High
	case "medium", "med":
		return Medium
	default:
		return Low
	}
}

func printText(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("prodready: no findings. 👍")
		return
	}
	byFile := map[string][]Finding{}
	var order []string
	for _, f := range findings {
		if _, ok := byFile[f.File]; !ok {
			order = append(order, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	var high, med, low int
	for _, file := range order {
		fmt.Printf("\n%s\n", file)
		for _, f := range byFile[file] {
			fmt.Printf("  [%-6s] %s  %s\n", f.Sev, f.Rule, f.Title)
			fmt.Printf("           ↳ %s\n", f.Fix)
			switch f.Severity {
			case High:
				high++
			case Medium:
				med++
			default:
				low++
			}
		}
	}
	fmt.Printf("\n%d findings: %d HIGH, %d MEDIUM, %d LOW\n", len(findings), high, med, low)
}

func printJSON(findings []Finding) {
	if findings == nil {
		findings = []Finding{}
	}
	b, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println(string(b))
}
