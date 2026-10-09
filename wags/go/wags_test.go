package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoWagsEngine(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wags_go_test_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	targetFile := filepath.Join(tempDir, "service.go")
	if err := os.WriteFile(targetFile, []byte("package main\n\nfunc Run() {}\n"), 0644); err != nil {
		t.Fatalf("Failed to write target file: %v", err)
	}

	ws, err := NewWagsWorkspace(tempDir)
	if err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	manifest, err := ws.InitReview(targetFile, "code", "Go Service", "go-gemini", "")
	if err != nil {
		t.Fatalf("InitReview failed: %v", err)
	}
	reviewID := manifest["review_id"].(string)

	// Register reviewer
	if err := ws.RegisterReviewer(reviewID, "devin-go", "secret123", "reviewer"); err != nil {
		t.Fatalf("RegisterReviewer failed: %v", err)
	}

	// Submit P2 finding & approve
	finding := Finding{
		ID:             "devin-go-P2-01",
		Severity:       "P2",
		Surface:        "core",
		Finding:        "Add context parameter to Run()",
		Evidence:       "service.go:3",
		Recommendation: "Use ctx context.Context",
	}
	entry, err := ws.SubmitEntry(reviewID, "devin-go", "review", []Finding{finding}, "approve", "secret123")
	if err != nil {
		t.Fatalf("SubmitEntry failed: %v", err)
	}
	if entry.Sequence != 1 {
		t.Errorf("Expected sequence 1, got %d", entry.Sequence)
	}

	// Verify integrity
	valid, errorsList, err := ws.VerifyReview(reviewID, map[string]string{"devin-go": "secret123"})
	if err != nil || !valid {
		t.Fatalf("VerifyReview failed: %v, errors: %v", err, errorsList)
	}

	// Converge
	conv, err := ws.ConvergeReview(reviewID)
	if err != nil {
		t.Fatalf("ConvergeReview failed: %v", err)
	}
	if conv["overall_verdict"] != "APPROVE" {
		t.Errorf("Expected verdict APPROVE, got %s", conv["overall_verdict"])
	}
}

func newResWS(t *testing.T) (*WagsWorkspace, string, func()) {
	dir, err := os.MkdirTemp("", "wags_go_res_")
	if err != nil {
		t.Fatal(err)
	}
	tgt := filepath.Join(dir, "t.md")
	_ = os.WriteFile(tgt, []byte("# t\n"), 0644)
	ws, err := NewWagsWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ws.InitReview(tgt, "doc", "res", "author", "rev-res-go")
	if err != nil {
		t.Fatal(err)
	}
	return ws, m["review_id"].(string), func() { os.RemoveAll(dir) }
}

func f(id, sev string) Finding {
	return Finding{ID: id, Severity: sev, Surface: "docs", Finding: "x", Evidence: "x:1", Recommendation: "fix"}
}

func TestGoResolvesAndLatestVerdict(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	e1, _ := ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("a-P1-01", "P1"), f("a-P1-02", "P1")}, "request_changes", "")
	e2, _ := ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("a-r2-P1-01", "P1")}, "request_changes", "")
	if _, err := ws.SubmitEntryWithMetadata(rid, "rev-a", "review", []Finding{f("a-r3-N-01", "N")}, "approve", "",
		map[string]interface{}{"resolves": []interface{}{"a-r2-P1-01"}, "supersedes": []interface{}{e1.EntryHash}}); err != nil {
		t.Fatal(err)
	}
	_ = e2
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	ok, errs, _ := ws.VerifyReview(rid, nil)
	if !ok {
		t.Fatalf("verify: %v", errs)
	}
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "APPROVE" {
		t.Fatalf("want APPROVE got %v (%v)", c["overall_verdict"], c["rationale"])
	}
	if n := c["summary"].(map[string]interface{})["findings_by_severity"].(map[string]int)["P1"]; n != 0 {
		t.Fatalf("want 0 open P1, got %d", n)
	}
}

func TestGoCannotResolveOthersAndP0Veto(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("a-P0-01", "P0")}, "block", "")
	if _, err := ws.SubmitEntryWithMetadata(rid, "rev-b", "review", nil, "approve", "",
		map[string]interface{}{"resolves": []interface{}{"a-P0-01"}}); err == nil {
		t.Fatal("expected cross-reviewer resolve to be rejected")
	}
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "BLOCK" {
		t.Fatalf("open P0 must veto, got %v", c["overall_verdict"])
	}
	_, err := ws.SubmitEntryWithMetadata(rid, "rev-a", "review", nil, "approve", "",
		map[string]interface{}{"resolves": []interface{}{"a-P0-01"}})
	if err != nil {
		t.Fatal(err)
	}
	c, _ = ws.ConvergeReview(rid)
	if c["overall_verdict"] != "APPROVE" {
		t.Fatalf("resolved P0 should clear, got %v", c["overall_verdict"])
	}
}

func TestGoCanonicalJSONNoHTMLEscape(t *testing.T) {
	b, _ := canonicalJSON(map[string]interface{}{"b": ">=1.4 & <2 →", "a": 1})
	if string(b) != `{"a":1,"b":">=1.4 & <2 →"}` {
		t.Fatalf("got %s", b)
	}
}
