package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	rid := m["review_id"].(string)
	for _, r := range []string{"rev-a", "rev-b"} {
		if err := ws.RegisterReviewer(rid, r, "", "reviewer"); err != nil {
			t.Fatal(err)
		}
	}
	return ws, rid, func() { os.RemoveAll(dir) }
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
	if n := c["summary"].(map[string]interface{})["open_findings_by_severity"].(map[string]int)["P1"]; n != 0 {
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

func TestGoReraisedP0AfterResolveVetoes(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P0")}, "block", "")
	if _, err := ws.SubmitEntryWithMetadata(rid, "rev-a", "review", nil, "approve", "", map[string]interface{}{"resolves": []interface{}{"X"}}); err != nil {
		t.Fatal(err)
	}
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P0")}, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	if ok, errs, _ := ws.VerifyReview(rid, nil); !ok {
		t.Fatal(errs)
	}
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "BLOCK" {
		t.Fatalf("re-raised P0 must veto, got %v", c["overall_verdict"])
	}
}

func TestGoReorderedStreamBlocksAndUnregisteredExcluded(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "block", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	p := filepath.Join(ws.ReviewsDir, rid, "rev-a.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	_ = os.WriteFile(p, []byte(lines[1]+"\n"+lines[0]+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(ws.ReviewsDir, rid, "zz.jsonl"), []byte(`{"verdict":"approve","findings":[]}`+"\n"), 0644)
	if ok, _, _ := ws.VerifyReview(rid, nil); ok {
		t.Fatal("reordered stream should fail verify")
	}
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "BLOCK" {
		t.Fatalf("invalid registered stream must block, got %v", c["overall_verdict"])
	}
	if u := c["unregistered_streams"].([]string); len(u) != 1 || u[0] != "zz" {
		t.Fatalf("unregistered not reported: %v", u)
	}
	if inv := c["invalid_streams"].([]map[string]interface{}); len(inv) != 2 { // rev-a (reordered) + zz (unregistered with content, fail closed)
		t.Fatalf("invalid not reported: %v", inv)
	}
}

func TestGoSubmitValidation(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	if _, err := ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("x", "critical")}, "approve", ""); err == nil {
		t.Fatal("unknown severity should be rejected")
	}
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P1")}, "request_changes", "")
	for _, md := range []map[string]interface{}{{"resolves": nil}, {"supersedes": nil}, {"supersedes": []interface{}{"nope"}}} {
		if _, err := ws.SubmitEntryWithMetadata(rid, "rev-a", "review", nil, "approve", "", md); err == nil {
			t.Fatalf("expected rejection for %v", md)
		}
	}
}

func TestGoCanonicalJSONPythonParity(t *testing.T) {
	line := `{"metadata":{"one":1.0,"negz":-0.0,"exp":1e-07,"big":100000000000000000000},"findings":[{"finding":"lit \\u2028 real ` + "\u2028" + ` <b>&"}]}`
	var e StreamEntry
	if err := decodeEntry(line, &e); err != nil {
		t.Fatal(err)
	}
	b, _ := canonicalJSON(map[string]interface{}{"metadata": e.Metadata, "findings": e.Findings})
	want := `{"findings":[{"finding":"lit \\u2028 real ` + "\u2028" + ` <b>&"}],"metadata":{"big":100000000000000000000,"exp":1e-07,"negz":-0.0,"one":1.0}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestGoAcceptsLegacyGoHash(t *testing.T) {
	ws, err := NewWagsWorkspace(filepath.Join("..", "..", "tests", "fixtures", "legacy-go-010"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, errs, _ := ws.VerifyReview("rev-legacy-go-010", nil); !ok {
		t.Fatalf("legacy entry should verify: %v", errs)
	}
}

func writeJSON(t *testing.T, p string, v interface{}) {
	b, _ := json.Marshal(v)
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestGoAnchorDetectsTruncationAndDeletion(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P0")}, "block", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	if c, _ := ws.ConvergeReview(rid); c["overall_verdict"] != "BLOCK" {
		t.Fatal("baseline should block")
	}
	p := filepath.Join(ws.ReviewsDir, rid, "rev-a.jsonl")
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Split(string(b), "\n")[0]+"\n"), 0644)
	if ok, _, _ := ws.VerifyReview(rid, nil); !ok {
		t.Fatal("truncated chain still verifies (expected; anchor must catch it)")
	}
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "BLOCK" || len(c["regressed_streams"].([]map[string]interface{})) != 1 {
		t.Fatalf("truncation must BLOCK via anchor: %v", c["rationale"])
	}
	if c, _ := ws.ConvergeReview(rid); c["overall_verdict"] != "BLOCK" {
		t.Fatal("regression BLOCK must persist")
	}
	_ = os.Remove(p)
	if c, _ := ws.ConvergeReview(rid); c["overall_verdict"] != "BLOCK" {
		t.Fatal("deleted stream must BLOCK")
	}
}

func TestGoDeregisteredVetoerBlocks(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P0")}, "block", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	rp := filepath.Join(ws.ReviewsDir, rid, "reviewers.json")
	reg := registeredReviewers(filepath.Join(ws.ReviewsDir, rid))
	delete(reg, "rev-a")
	writeJSON(t, rp, reg)
	if ok, _, _ := ws.VerifyReview(rid, nil); ok {
		t.Fatal("unregistered stream with entries must fail verify")
	}
	if c, _ := ws.ConvergeReview(rid); c["overall_verdict"] != "BLOCK" {
		t.Fatalf("got %v", c["overall_verdict"])
	}
}

func TestGoWipedRegistryNoLegacyOn020(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "defer", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "defer", "")
	writeJSON(t, filepath.Join(ws.ReviewsDir, rid, "reviewers.json"), map[string]interface{}{})
	_, _ = ws.SubmitEntry(rid, "e1", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "e2", "review", nil, "approve", "")
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "BLOCK" || c["registry_mode"] != "registered" {
		t.Fatalf("got %v / %v", c["overall_verdict"], c["registry_mode"])
	}
}

func TestGoLegacyHashOnlyFor010AndNotAfterCanonical(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	revDir := filepath.Join(ws.ReviewsDir, rid)
	e, _ := ws.SubmitEntry(rid, "rev-a", "review", []Finding{{ID: "x", Severity: "P2", Finding: "<b> & c"}}, "approve", "")
	// restamp with legacy hash
	legacy, _ := computeSHA256OfPayload(entryPayload(e), true)
	e.EntryHash = legacy
	b, _ := json.Marshal(e)
	_ = os.WriteFile(filepath.Join(revDir, "rev-a.jsonl"), append(b, '\n'), 0644)
	if ok, _, _ := ws.VerifyReview(rid, nil); ok {
		t.Fatal("legacy hash must be rejected on a 0.2.0 target")
	}
	// 0.1.0 target: legacy alone ok
	var tg map[string]interface{}
	tb, _ := os.ReadFile(filepath.Join(revDir, "target.json"))
	_ = json.Unmarshal(tb, &tg)
	tg["protocol_version"] = "0.1.0"
	writeJSON(t, filepath.Join(revDir, "target.json"), tg)
	if ok, errs, _ := ws.VerifyReview(rid, nil); !ok {
		t.Fatalf("legacy hash should verify on 0.1.0 target: %v", errs)
	}
	// canonical then legacy: rejected
	_ = os.WriteFile(filepath.Join(revDir, "rev-a.jsonl"), nil, 0644)
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	e2, _ := ws.SubmitEntry(rid, "rev-a", "review", []Finding{{ID: "y", Severity: "P2", Finding: "<&>"}}, "approve", "")
	data, _ := os.ReadFile(filepath.Join(revDir, "rev-a.jsonl"))
	first := strings.Split(string(data), "\n")[0]
	l2, _ := computeSHA256OfPayload(entryPayload(e2), true)
	e2.EntryHash = l2
	b2, _ := json.Marshal(e2)
	_ = os.WriteFile(filepath.Join(revDir, "rev-a.jsonl"), []byte(first+"\n"+string(b2)+"\n"), 0644)
	ok, errs, _ := ws.VerifyReview(rid, nil)
	if ok || !strings.Contains(strings.Join(errs, " "), "legacy-form") {
		t.Fatalf("legacy after canonical must fail: %v", errs)
	}
}

func TestGoFloat32AndEmptyRefs(t *testing.T) {
	b, _ := canonicalJSON(map[string]interface{}{"f": float32(0.1)})
	if string(b) != `{"f":0.10000000149011612}` {
		t.Fatalf("float32: %s", b)
	}
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P1")}, "request_changes", "")
	for _, md := range []map[string]interface{}{{"resolves": []interface{}{}}, {"supersedes": []interface{}{}}} {
		if _, err := ws.SubmitEntryWithMetadata(rid, "rev-a", "review", nil, "approve", "", md); err == nil {
			t.Fatalf("empty refs should be rejected: %v", md)
		}
	}
}
