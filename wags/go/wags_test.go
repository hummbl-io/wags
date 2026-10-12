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
	if err := ws.RegisterReviewer(reviewID, "alice-go", "secret123", "reviewer"); err != nil {
		t.Fatalf("RegisterReviewer failed: %v", err)
	}

	// Submit P2 finding & approve
	finding := Finding{
		ID:             "alice-go-P2-01",
		Severity:       "P2",
		Surface:        "core",
		Finding:        "Add context parameter to Run()",
		Evidence:       "service.go:3",
		Recommendation: "Use ctx context.Context",
	}
	entry, err := ws.SubmitEntry(reviewID, "alice-go", "review", []Finding{finding}, "approve", "secret123")
	if err != nil {
		t.Fatalf("SubmitEntry failed: %v", err)
	}
	if entry.Sequence != 1 {
		t.Errorf("Expected sequence 1, got %d", entry.Sequence)
	}

	// Verify integrity
	valid, errorsList, err := ws.VerifyReview(reviewID, map[string]string{"alice-go": "secret123"})
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
	if c["overall_verdict"] != "DEFER" {
		t.Fatalf("rev-b has not voted: quorum pending, got %v", c["overall_verdict"])
	}
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
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
	if ok, _, _ := ws.VerifyReview(rid, nil); ok {
		t.Fatal("0.1.0 target edited into a 0.2.0 workspace (index marker) must still reject legacy")
	}
	// scrubbing index.json is not enough: the entry carries a hash-chained wags_protocol marker
	writeJSON(t, ws.IndexFile, map[string]interface{}{"protocol_version": "0.1.0", "reviews": map[string]interface{}{}})
	if ok, _, _ := ws.VerifyReview(rid, nil); ok {
		t.Fatal("chained wags_protocol marker must still reject legacy")
	}
	// genuine 0.1.0 review: entry written while target is 0.1.0 (unmarked), then legacy-stamped
	_ = os.WriteFile(filepath.Join(revDir, "rev-a.jsonl"), nil, 0644)
	e, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{{ID: "x", Severity: "P2", Finding: "<b> & c"}}, "approve", "")
	if _, marked := e.Metadata["wags_protocol"]; marked {
		t.Fatal("0.1.0 targets must not get the marker")
	}
	legacy, _ = computeSHA256OfPayload(entryPayload(e), true)
	e.EntryHash = legacy
	b, _ = json.Marshal(e)
	_ = os.WriteFile(filepath.Join(revDir, "rev-a.jsonl"), append(b, '\n'), 0644)
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

func downgrade(t *testing.T, revDir string) {
	var tg map[string]interface{}
	b, _ := os.ReadFile(filepath.Join(revDir, "target.json"))
	_ = json.Unmarshal(b, &tg)
	tg["protocol_version"] = "0.1.0"
	writeJSON(t, filepath.Join(revDir, "target.json"), tg)
	writeJSON(t, filepath.Join(revDir, "reviewers.json"), map[string]interface{}{})
}

func TestGoDowngradeBlocks(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		ws, rid, done := newResWS(t)
		revDir := filepath.Join(ws.ReviewsDir, rid)
		_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "defer", "")
		_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "defer", "")
		if anchored {
			_, _ = ws.ConvergeReview(rid)
		}
		_, _ = ws.SubmitEntry(rid, "evil", "review", nil, "approve", "")
		_, _ = ws.SubmitEntry(rid, "evil2", "review", nil, "approve", "")
		downgrade(t, revDir)
		c, _ := ws.ConvergeReview(rid)
		if c["overall_verdict"] != "BLOCK" || c["registry_mode"] != "registered" {
			t.Fatalf("anchored=%v: got %v / %v", anchored, c["overall_verdict"], c["registry_mode"])
		}
		if anchored {
			if len(c["anchor_problems"].([]string)) == 0 {
				t.Fatal("expected anchor_problems")
			}
			if c2, _ := ws.ConvergeReview(rid); c2["overall_verdict"] != "BLOCK" {
				t.Fatal("downgrade BLOCK must persist")
			}
		}
		done()
	}
}

func TestGoUnparseableConvergedAndAnchorStatus(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	c, _ := ws.ConvergeReview(rid)
	if c["anchor_status"] != "absent" || c["overall_verdict"] != "APPROVE" {
		t.Fatalf("first: %v %v", c["anchor_status"], c["overall_verdict"])
	}
	c, _ = ws.ConvergeReview(rid)
	if c["anchor_status"] != "present" || c["overall_verdict"] != "APPROVE" {
		t.Fatalf("second: %v %v (%v)", c["anchor_status"], c["overall_verdict"], c["rationale"])
	}
	_ = os.WriteFile(filepath.Join(ws.ReviewsDir, rid, "converged.json"), []byte("garbage"), 0644)
	c, _ = ws.ConvergeReview(rid)
	if c["anchor_status"] != "unparseable" || c["overall_verdict"] != "BLOCK" {
		t.Fatalf("garbage: %v %v", c["anchor_status"], c["overall_verdict"])
	}
	if c, _ = ws.ConvergeReview(rid); c["overall_verdict"] != "BLOCK" {
		t.Fatal("anchor_lost BLOCK must persist")
	}
}

func TestGo010TargetWithResolvesBlocks(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	revDir := filepath.Join(ws.ReviewsDir, rid)
	var tg map[string]interface{}
	b, _ := os.ReadFile(filepath.Join(revDir, "target.json"))
	_ = json.Unmarshal(b, &tg)
	tg["protocol_version"] = "0.1.0"
	writeJSON(t, filepath.Join(revDir, "target.json"), tg)
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", []Finding{f("X", "P1")}, "request_changes", "")
	_, _ = ws.SubmitEntryWithMetadata(rid, "rev-a", "review", nil, "approve", "", map[string]interface{}{"resolves": []interface{}{"X"}})
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	if c, _ := ws.ConvergeReview(rid); c["overall_verdict"] != "BLOCK" {
		t.Fatalf("got %v", c["overall_verdict"])
	}
}

func TestGoQuorumAndUnregisteredMessage(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_ = ws.RegisterReviewer(rid, "silent", "", "reviewer")
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	if c, _ := ws.ConvergeReview(rid); c["overall_verdict"] != "DEFER" || c["quorum_met"] != false {
		t.Fatalf("quorum: %v", c["overall_verdict"])
	}
	if c, _ := ws.ConvergeReviewOpts(rid, intPtr(2)); c["overall_verdict"] != "APPROVE" {
		t.Fatalf("min_quorum=2: %v", c["overall_verdict"])
	}
	_, _ = ws.SubmitEntry(rid, "zz", "review", nil, "approve", "")
	_, errs, _ := ws.VerifyReview(rid, nil)
	joined := strings.Join(errs, "|")
	if strings.Contains(joined, "line 0") || !strings.Contains(joined, "has 1 entry but reviewer is not registered") {
		t.Fatalf("message: %v", errs)
	}
}

func intPtr(n int) *int { return &n }

func TestGoMinQuorumValidation(t *testing.T) {
	for _, bad := range []string{"0", "-1", "1.5", "abc", "true", " 2", "²"} {
		if _, err := ParseMinQuorum(bad); err == nil {
			t.Fatalf("CLI value %q should be rejected", bad)
		}
	}
	if v, err := ParseMinQuorum("2"); err != nil || *v != 2 {
		t.Fatal("2 should parse")
	}
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	for _, bad := range []int{0, -1, -5} {
		if _, err := ws.ConvergeReviewOpts(rid, intPtr(bad)); err == nil {
			t.Fatalf("API min_quorum %d should be rejected", bad)
		}
	}
	c, _ := ws.ConvergeReviewOpts(rid, intPtr(5))
	q := c["quorum"].(map[string]interface{})
	if c["overall_verdict"] != "DEFER" || q["warning"] == nil || q["min_quorum"] != 5 {
		t.Fatalf("above registered: %v %v", c["overall_verdict"], q)
	}
}

func TestGoChainedMarkerBlocksScrubbedDowngrade(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	revDir := filepath.Join(ws.ReviewsDir, rid)
	e, _ := ws.SubmitEntry(rid, "rev-a", "review", nil, "defer", "")
	if e.Metadata["wags_protocol"] != ProtocolVersion {
		t.Fatal("new 0.2.0 entries must carry wags_protocol")
	}
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "defer", "")
	_, _ = ws.SubmitEntry(rid, "evil", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "evil2", "review", nil, "approve", "")
	downgrade(t, revDir)
	writeJSON(t, ws.IndexFile, map[string]interface{}{"protocol_version": "0.1.0", "reviews": map[string]interface{}{}})
	c, _ := ws.ConvergeReview(rid)
	if c["overall_verdict"] != "BLOCK" || c["registry_mode"] != "registered" {
		t.Fatalf("N1: %v %v", c["overall_verdict"], c["registry_mode"])
	}
}

func TestGoPresentNoContext(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	c, _ := ws.ConvergeReview(rid)
	p := filepath.Join(ws.ReviewsDir, rid, "converged.json")
	delete(c, "anchor_context")
	writeJSON(t, p, c)
	c2, _ := ws.ConvergeReview(rid)
	if c2["anchor_status"] != "present_no_context" || c2["overall_verdict"] != "APPROVE" {
		t.Fatalf("%v %v", c2["anchor_status"], c2["overall_verdict"])
	}
}

func TestGoParallelConverge(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	_, _ = ws.ConvergeReview(rid)
	res := make(chan string, 32)
	for i := 0; i < 32; i++ {
		go func() {
			c, err := ws.ConvergeReview(rid)
			if err != nil {
				res <- "ERR " + err.Error()
				return
			}
			res <- c["overall_verdict"].(string)
		}()
	}
	for i := 0; i < 32; i++ {
		if v := <-res; v != "APPROVE" {
			t.Fatalf("parallel converge got %s", v)
		}
	}
}

func TestGoMinQuorumEmptyAndHuge(t *testing.T) {
	for _, bad := range []string{"", "100000000000000000000", "1000001"} {
		_, err := ParseMinQuorum(bad)
		want := "min_quorum must be a positive integer (1..1000000); got '" + bad + "'"
		if err == nil || err.Error() != want {
			t.Fatalf("%q: got %v", bad, err)
		}
	}
	if err := ValidateMinQuorum(intPtr(MaxMinQuorum + 1)); err == nil {
		t.Fatal("API above MaxMinQuorum must be rejected")
	}
}

func TestGoConvergeWriteFailurePropagates(t *testing.T) {
	ws, rid, done := newResWS(t)
	defer done()
	_, _ = ws.SubmitEntry(rid, "rev-a", "review", nil, "approve", "")
	_, _ = ws.SubmitEntry(rid, "rev-b", "review", nil, "approve", "")
	revDir := filepath.Join(ws.ReviewsDir, rid)
	_ = os.Mkdir(filepath.Join(revDir, "converged.json"), 0755)
	if _, err := ws.ConvergeReview(rid); err == nil || !strings.Contains(err.Error(), "failed to write converged.json") {
		t.Fatalf("expected write error, got %v", err)
	}
	ents, _ := os.ReadDir(revDir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestGoAtomicWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	if err := atomicWriteFile(p, []byte(`{"ok":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(p, []byte(`{"ok":2}`)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != `{"ok":2}` {
		t.Fatalf("got %s", b)
	}
	if err := atomicWriteFile(filepath.Join(dir, "missing", "x.json"), []byte("{}")); err == nil {
		t.Fatal("write into missing dir must error")
	}
}
