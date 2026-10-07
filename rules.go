package main

import (
	"regexp"
	"strings"
)

// Severity ranks a finding.
type Severity int

const (
	Low Severity = iota
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Finding is one problem found in one file.
type Finding struct {
	File     string   `json:"file"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	Sev      string   `json:"severity"`
	Title    string   `json:"title"`
	Fix      string   `json:"fix"`
}

// workloadKinds are the Kubernetes kinds whose pod templates we lint.
var workloadKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Pod": true, "Job": true, "CronJob": true, "ReplicaSet": true,
	"Rollout": true, // Argo Rollouts
}

var (
	reKind     = regexp.MustCompile(`(?m)^\s*kind:\s*["']?([A-Za-z]+)`)
	reImage    = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^"'\s]+)`)
	reEnvName  = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|credential|private[_-]?key)`)
	secretHint = reEnvName
)

// LintYAML runs the Kubernetes checks over one YAML file's content.
// It splits on document separators and lints each workload document.
func LintYAML(file, content string) []Finding {
	var out []Finding
	for _, doc := range splitYAMLDocs(content) {
		kind := firstSubmatch(reKind, doc)
		if !workloadKinds[kind] {
			continue
		}
		out = append(out, lintWorkloadDoc(file, doc)...)
	}
	return out
}

func lintWorkloadDoc(file, doc string) []Finding {
	var f []Finding
	add := func(rule string, sev Severity, title, fix string) {
		f = append(f, Finding{File: file, Rule: rule, Severity: sev, Sev: sev.String(), Title: title, Fix: fix})
	}

	// PR001 — image tag
	for _, img := range allSubmatches(reImage, doc) {
		if isMutableImage(img) {
			add("PR001", High, "Image is not pinned: "+img,
				"Pin a version or digest, e.g. image@sha256:... — :latest is unreproducible and blocks clean rollbacks.")
			break
		}
	}
	// PR002 — resource limits
	if !strings.Contains(doc, "limits:") {
		add("PR002", Medium, "No resource limits set",
			"Set resources.limits (cpu, memory, ephemeral-storage) so one pod can't starve the node.")
	}
	// PR003 — privileged
	if regexp.MustCompile(`(?m)privileged:\s*true`).MatchString(doc) {
		add("PR003", High, "Container runs privileged",
			"Remove privileged: true. Grant only the specific capabilities the workload needs.")
	}
	// PR004 — runAsNonRoot
	if !regexp.MustCompile(`(?m)runAsNonRoot:\s*true`).MatchString(doc) {
		add("PR004", High, "Not asserted to run as non-root",
			"Set securityContext.runAsNonRoot: true and a runAsUser > 10000.")
	}
	// PR005 — allowPrivilegeEscalation
	if !regexp.MustCompile(`(?m)allowPrivilegeEscalation:\s*false`).MatchString(doc) {
		add("PR005", Medium, "allowPrivilegeEscalation not disabled",
			"Set securityContext.allowPrivilegeEscalation: false.")
	}
	// PR006 — readOnlyRootFilesystem
	if !regexp.MustCompile(`(?m)readOnlyRootFilesystem:\s*true`).MatchString(doc) {
		add("PR006", Medium, "Root filesystem is writable",
			"Set securityContext.readOnlyRootFilesystem: true; mount an emptyDir for paths that need writes.")
	}
	// PR007 — drop ALL capabilities
	if !(strings.Contains(doc, "drop:") && strings.Contains(doc, "ALL")) {
		add("PR007", Medium, "Linux capabilities not dropped",
			"Set securityContext.capabilities.drop: [\"ALL\"] and add back only what's needed.")
	}
	// PR008 — probes
	if !strings.Contains(doc, "livenessProbe:") && !strings.Contains(doc, "readinessProbe:") {
		add("PR008", Medium, "No liveness or readiness probe",
			"Add a readinessProbe (and usually a livenessProbe) so Kubernetes can route and restart safely.")
	}
	// PR009 — plaintext secret in env
	if name := plaintextSecretEnv(doc); name != "" {
		add("PR009", High, "Possible plaintext secret in env: "+name,
			"Move it to a Secret and use valueFrom.secretKeyRef instead of a literal value.")
	}
	// PR010 — docker socket mount
	if strings.Contains(doc, "docker.sock") {
		add("PR010", High, "Docker socket mounted into container",
			"Remove the /var/run/docker.sock hostPath mount — it's a direct container-escape path to the host.")
	}
	// PR011 — seccomp
	if !strings.Contains(doc, "seccompProfile") {
		add("PR011", Low, "No seccomp profile set",
			"Set securityContext.seccompProfile.type: RuntimeDefault.")
	}
	return f
}

// LintDockerfile runs the Dockerfile checks.
func LintDockerfile(file, content string) []Finding {
	var f []Finding
	add := func(rule string, sev Severity, title, fix string) {
		f = append(f, Finding{File: file, Rule: rule, Severity: sev, Sev: sev.String(), Title: title, Fix: fix})
	}
	hasUser := false
	lines := strings.Split(content, "\n")
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		up := strings.ToUpper(t)
		switch {
		case strings.HasPrefix(up, "FROM "):
			ref := strings.Fields(t)[1]
			// ignore build-stage aliases like "AS build"
			if isMutableImage(ref) {
				add("PR020", Medium, "Base image not pinned: "+ref,
					"Pin a version or digest in FROM — :latest makes builds unreproducible.")
			}
		case strings.HasPrefix(up, "USER "):
			hasUser = true
		case strings.HasPrefix(up, "ADD ") && !strings.Contains(t, "http"):
			add("PR022", Low, "ADD used for local files",
				"Prefer COPY for local files; ADD has surprising unpack/remote behavior.")
		}
		if strings.Contains(t, "curl") && strings.Contains(t, "| sh") {
			add("PR023", Medium, "Piping a remote script into a shell",
				"Avoid curl | sh in images — pin and verify what you install.")
		}
	}
	if !hasUser {
		add("PR021", High, "No USER set — image runs as root",
			"Add a non-root USER (e.g. a uid >10000) in the final stage.")
	}
	return f
}

// --- helpers ---

func splitYAMLDocs(content string) []string {
	return regexp.MustCompile(`(?m)^---\s*$`).Split(content, -1)
}

// isMutableImage reports whether an image reference is unpinned (:latest or no tag).
func isMutableImage(ref string) bool {
	if strings.Contains(ref, "@sha256:") {
		return false // digest-pinned
	}
	// strip any registry host:port before looking for the tag colon
	name := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		name = ref[i+1:]
	}
	if !strings.Contains(name, ":") {
		return true // no tag → latest
	}
	tag := name[strings.LastIndex(name, ":")+1:]
	return tag == "latest" || tag == ""
}

// plaintextSecretEnv finds an env entry whose name looks secret-ish and that
// uses a literal `value:` rather than valueFrom. Returns the name, or "".
func plaintextSecretEnv(doc string) string {
	lines := strings.Split(doc, "\n")
	for i, ln := range lines {
		m := regexp.MustCompile(`(?i)name:\s*["']?([A-Za-z0-9_]+)`).FindStringSubmatch(ln)
		if m == nil || !secretHint.MatchString(m[1]) {
			continue
		}
		// look at the next 2 lines for a literal value (not valueFrom)
		for j := i + 1; j < len(lines) && j <= i+2; j++ {
			nx := strings.TrimSpace(lines[j])
			if strings.HasPrefix(nx, "value:") {
				return m[1]
			}
			if strings.HasPrefix(nx, "valueFrom:") {
				break
			}
		}
	}
	return ""
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func allSubmatches(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}
