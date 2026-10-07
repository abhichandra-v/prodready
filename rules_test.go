package main

import "testing"

const badDeploy = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          env:
            - name: DB_PASSWORD
              value: hunter2
`

const goodDeploy = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/me/app@sha256:abc123
          resources:
            limits: { cpu: 500m, memory: 256Mi }
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef: { name: s, key: p }
`

func rules(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Rule] = true
	}
	return m
}

func TestBadDeploymentFlagged(t *testing.T) {
	got := rules(LintYAML("bad.yaml", badDeploy))
	for _, want := range []string{"PR001", "PR002", "PR004", "PR009"} {
		if !got[want] {
			t.Errorf("expected %s to fire on bad deployment", want)
		}
	}
}

func TestGoodDeploymentClean(t *testing.T) {
	got := LintYAML("good.yaml", goodDeploy)
	if len(got) != 0 {
		t.Errorf("expected no findings on hardened deployment, got %d: %+v", len(got), got)
	}
}

func TestNonWorkloadIgnored(t *testing.T) {
	svc := "kind: Service\nmetadata:\n  name: x\n"
	if got := LintYAML("svc.yaml", svc); len(got) != 0 {
		t.Errorf("Service should not be linted, got %+v", got)
	}
}

func TestImagePinning(t *testing.T) {
	cases := map[string]bool{
		"nginx":                      true,
		"nginx:latest":               true,
		"nginx:1.27":                 false,
		"ghcr.io/x/y:1.2.3":          false,
		"registry:5000/x":            true,
		"ghcr.io/x/y@sha256:deadbee": false,
	}
	for ref, wantMutable := range cases {
		if got := isMutableImage(ref); got != wantMutable {
			t.Errorf("isMutableImage(%q)=%v, want %v", ref, got, wantMutable)
		}
	}
}

func TestDockerfileChecks(t *testing.T) {
	df := "FROM python:latest\nCOPY . .\n"
	got := rules(LintDockerfile("Dockerfile", df))
	if !got["PR020"] {
		t.Error("expected PR020 (unpinned base) ")
	}
	if !got["PR021"] {
		t.Error("expected PR021 (no USER)")
	}
}

func TestDockerfileCleanWithUser(t *testing.T) {
	df := "FROM python:3.12-slim\nUSER 65532\n"
	got := rules(LintDockerfile("Dockerfile", df))
	if got["PR020"] || got["PR021"] {
		t.Errorf("hardened Dockerfile should be clean, got %+v", got)
	}
}
