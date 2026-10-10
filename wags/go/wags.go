// Package main implements wags v0.2.0 - polyglot air-gappable multi-agent peer review protocol.
// 100% Go standard library (zero external dependencies).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ProtocolVersion = "0.2.0"
	GenesisHash     = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Finding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"` // P0, P1, P2, P3, N
	Surface        string `json:"surface"`
	Finding        string `json:"finding"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

type StreamEntry struct {
	Sequence   int                      `json:"sequence"`
	Timestamp  string                   `json:"timestamp"`
	ReviewID   string                   `json:"review_id"`
	Reviewer   string                   `json:"reviewer"`
	Phase      string                   `json:"phase"`
	PrevHash   string                   `json:"prev_hash"`
	Findings   []map[string]interface{} `json:"findings"`
	Verdict    string                   `json:"verdict,omitempty"`
	RebuttalTo string                   `json:"rebuttal_to,omitempty"`
	Metadata   map[string]interface{}   `json:"metadata,omitempty"`
	EntryHash  string                   `json:"entry_hash"`
	Signature  string                   `json:"signature,omitempty"`
}

// atomicWriteFile writes via a temp file + rename so concurrent readers never
// observe a partially written file. Mirrors Python _atomic_write_json.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, 0644)
	// Windows: renaming over a file another process holds open fails with an
	// access error. Retry briefly (~1s), then return the error (never drop it).
	var rerr error
	for attempt := 0; attempt < 20; attempt++ {
		if rerr = os.Rename(tmp, path); rerr == nil {
			break
		}
		if runtime.GOOS != "windows" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rerr != nil {
		os.Remove(tmp)
		return rerr
	}
	fsyncDir(dir)
	return nil
}

// fsyncDir makes the rename durable on POSIX; best effort / no-op on Windows.
func fsyncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}

func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// canonicalJSON reproduces Python's
// json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// byte for byte: keys sorted, no HTML escaping, non-ASCII (incl. U+2028/9)
// emitted raw, and numbers emitted from their original literal (json.Number)
// so Python floats such as 1.0, -0.0 and 1e-07 round-trip exactly.
func canonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func pyFloat(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		if math.IsNaN(f) {
			return "NaN"
		} else if f > 0 {
			return "Infinity"
		}
		return "-Infinity"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e16 {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if math.Signbit(f) && f == 0 {
			s = "-0"
		}
		return s + ".0"
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	// Python writes exponents with at least two digits: 1e-07
	if i := strings.IndexAny(s, "e"); i >= 0 {
		mant, exp := s[:i], s[i+1:]
		sign := "+"
		if exp[0] == '-' || exp[0] == '+' {
			sign, exp = exp[:1], exp[1:]
		}
		if len(exp) < 2 {
			exp = "0" + exp
		}
		s = mant + "e" + sign + exp
	}
	return s
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, x)
	case json.Number:
		buf.WriteString(string(x))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case float32:
		buf.WriteString(pyFloat(float64(x))) // Python sees the widened float64 value
	case float64:
		buf.WriteString(pyFloat(x))
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		arr := make([]interface{}, len(x))
		for i := range x {
			arr[i] = x[i]
		}
		return writeCanonical(buf, arr)
	case []map[string]interface{}:
		arr := make([]interface{}, len(x))
		for i := range x {
			arr[i] = x[i]
		}
		return writeCanonical(buf, arr)
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Python sorts by code point; Go sorts by UTF-8 bytes (same order)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// Fall back via a JSON round-trip with UseNumber.
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		var g interface{}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&g); err != nil {
			return err
		}
		return writeCanonical(buf, g)
	}
	return nil
}

// decodeEntry parses one JSONL line preserving numeric literals.
func decodeEntry(line string, e *StreamEntry) error {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	return dec.Decode(e)
}

func computeEntryHash(entry *StreamEntry) (string, error) {
	return computeSHA256OfPayload(entryPayload(entry), false)
}

func entryPayload(entry *StreamEntry) map[string]interface{} {
	payload := map[string]interface{}{
		"sequence":    entry.Sequence,
		"timestamp":   entry.Timestamp,
		"review_id":   entry.ReviewID,
		"reviewer":    entry.Reviewer,
		"phase":       entry.Phase,
		"prev_hash":   entry.PrevHash,
		"findings":    entry.Findings,
		"verdict":     nil,
		"rebuttal_to": nil,
		"metadata":    map[string]interface{}{},
	}
	if entry.Verdict != "" {
		payload["verdict"] = entry.Verdict
	}
	if entry.RebuttalTo != "" {
		payload["rebuttal_to"] = entry.RebuttalTo
	}
	if entry.Metadata != nil {
		payload["metadata"] = entry.Metadata
	}
	if entry.Findings == nil {
		payload["findings"] = []map[string]interface{}{}
	}
	return payload
}

// computeSHA256OfPayload hashes the payload. legacy=true reproduces the
// wags-go 0.1.0 encoding (encoding/json.Marshal: HTML-escaped <, >, & and
// escaped U+2028/U+2029), accepted on verify only.
func computeSHA256OfPayload(payload map[string]interface{}, legacy bool) (string, error) {
	var b []byte
	var err error
	if legacy {
		b, err = json.Marshal(payload)
	} else {
		b, err = canonicalJSON(payload)
	}
	if err != nil {
		return "", err
	}
	return computeSHA256(b), nil
}

func signEntry(entry *StreamEntry, secretKey string) error {
	h, err := computeEntryHash(entry)
	if err != nil {
		return err
	}
	entry.EntryHash = h
	if secretKey != "" {
		mac := hmac.New(sha256.New, []byte(secretKey))
		mac.Write([]byte(h))
		entry.Signature = hex.EncodeToString(mac.Sum(nil))
	} else {
		entry.Signature = ""
	}
	return nil
}

func verifyEntry(entry *StreamEntry, secretKey string) (bool, string) {
	return verifyEntryOpt(entry, secretKey, false)
}

// hashForm reports "canonical", "legacy" (wags-go 0.1.0) or "none".
func hashForm(entry *StreamEntry) string {
	if h, err := computeEntryHash(entry); err == nil && h == entry.EntryHash {
		return "canonical"
	}
	if h, err := computeSHA256OfPayload(entryPayload(entry), true); err == nil && h == entry.EntryHash {
		return "legacy"
	}
	return "none"
}

// verifyEntryOpt accepts the legacy wags-go 0.1.0 hash only when allowLegacy
// (protocol 0.1.0 targets, before any canonical-form entry in the stream).
func verifyEntryOpt(entry *StreamEntry, secretKey string, allowLegacy bool) (bool, string) {
	expectedHash, err := computeEntryHash(entry)
	if err != nil {
		return false, fmt.Sprintf("Hash calculation error: %v", err)
	}
	if allowLegacy && entry.EntryHash != expectedHash {
		if legacy, lerr := computeSHA256OfPayload(entryPayload(entry), true); lerr == nil && legacy == entry.EntryHash {
			expectedHash = legacy // accepted: wags-go 0.1.0 legacy encoding
		}
	}
	if entry.EntryHash != expectedHash {
		return false, fmt.Sprintf("Hash mismatch: stored %s != computed %s", entry.EntryHash, expectedHash)
	}
	if secretKey != "" && entry.Signature != "" {
		mac := hmac.New(sha256.New, []byte(secretKey))
		mac.Write([]byte(expectedHash))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(entry.Signature), []byte(expectedSig)) {
			return false, "HMAC signature verification failed"
		}
	}
	return true, "OK"
}

type WagsWorkspace struct {
	Root       string
	ReviewsDir string
	IndexFile  string
}

func NewWagsWorkspace(root string) (*WagsWorkspace, error) {
	if root == "" {
		if env := os.Getenv("WAGS_WORKSPACE"); env != "" {
			root = env
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			root = filepath.Join(cwd, ".wags")
		}
	}
	reviewsDir := filepath.Join(root, "reviews")
	indexFile := filepath.Join(root, "index.json")

	if err := os.MkdirAll(reviewsDir, 0755); err != nil {
		return nil, err
	}
	ws := &WagsWorkspace{
		Root:       root,
		ReviewsDir: reviewsDir,
		IndexFile:  indexFile,
	}
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		initIndex := map[string]interface{}{
			"protocol_version": ProtocolVersion,
			"reviews":          map[string]interface{}{},
		}
		data, _ := json.MarshalIndent(initIndex, "", "  ")
		_ = atomicWriteFile(indexFile, data)
	}
	return ws, nil
}

func (ws *WagsWorkspace) InitReview(targetPath, targetType, desc, initiator, customID string) (map[string]interface{}, error) {
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(absTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to read target: %w", err)
	}
	sha := computeSHA256(content)

	reviewID := customID
	if reviewID == "" {
		ts := time.Now().UTC().Format("20060102150405")
		reviewID = fmt.Sprintf("rev-%s-%s", ts, sha[:8])
	}
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	if err := os.MkdirAll(revDir, 0755); err != nil {
		return nil, err
	}

	manifest := map[string]interface{}{
		"protocol_version": ProtocolVersion,
		"review_id":        reviewID,
		"created_at":       time.Now().UTC().Format(time.RFC3339),
		"initiator":        initiator,
		"target": map[string]interface{}{
			"type":        targetType,
			"path":        absTarget,
			"sha256":      sha,
			"size_bytes":  len(content),
			"description": desc,
		},
		"phases":        []string{"review", "rebuttal", "meta-review", "convergence"},
		"current_phase": "review",
		"status":        "OPEN",
	}

	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := atomicWriteFile(filepath.Join(revDir, "target.json"), data); err != nil {
		return nil, err
	}
	_ = atomicWriteFile(filepath.Join(revDir, "reviewers.json"), []byte("{}"))

	// Record the review in index.json (parity with Python), including protocol_version.
	idx := map[string]interface{}{"protocol_version": ProtocolVersion, "reviews": map[string]interface{}{}}
	if b, err := os.ReadFile(ws.IndexFile); err == nil {
		_ = json.Unmarshal(b, &idx)
	}
	rv, ok := idx["reviews"].(map[string]interface{})
	if !ok {
		rv = map[string]interface{}{}
	}
	rv[reviewID] = map[string]interface{}{
		"target":           absTarget,
		"target_sha256":    sha,
		"created_at":       manifest["created_at"],
		"status":           "OPEN",
		"protocol_version": ProtocolVersion,
	}
	idx["reviews"] = rv
	if b, err := json.MarshalIndent(idx, "", "  "); err == nil {
		_ = atomicWriteFile(ws.IndexFile, b)
	}

	return manifest, nil
}

func (ws *WagsWorkspace) RegisterReviewer(reviewID, reviewerName, secretKey, role string) error {
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	if _, err := os.Stat(revDir); os.IsNotExist(err) {
		return fmt.Errorf("review %s not found", reviewID)
	}
	regFile := filepath.Join(revDir, "reviewers.json")
	reg := map[string]interface{}{}
	if b, err := os.ReadFile(regFile); err == nil {
		_ = json.Unmarshal(b, &reg)
	}
	reg[reviewerName] = map[string]interface{}{
		"registered_at": time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		"role":          role,
		"has_hmac":      secretKey != "",
	}
	if b, err := json.MarshalIndent(reg, "", "  "); err == nil {
		_ = atomicWriteFile(regFile, b)
	}
	streamPath := filepath.Join(revDir, reviewerName+".jsonl")
	if _, err := os.Stat(streamPath); os.IsNotExist(err) {
		f, err := os.Create(streamPath)
		if err != nil {
			return err
		}
		f.Close()
	}
	return nil
}

func (ws *WagsWorkspace) SubmitEntry(reviewID, reviewerName, phase string, findings []Finding, verdict string, secretKey string) (*StreamEntry, error) {
	return ws.SubmitEntryWithMetadata(reviewID, reviewerName, phase, findings, verdict, secretKey, nil)
}

// SubmitEntryWithMetadata appends an entry with optional metadata. If metadata
// carries "resolves" or "supersedes", the refs are validated against the
// reviewer's own earlier entries before anything is written.
func (ws *WagsWorkspace) SubmitEntryWithMetadata(reviewID, reviewerName, phase string, findings []Finding, verdict string, secretKey string, metadata map[string]interface{}) (*StreamEntry, error) {
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	streamPath := filepath.Join(revDir, reviewerName+".jsonl")

	lastSeq := 0
	lastHash := GenesisHash

	if data, err := os.ReadFile(streamPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var prev StreamEntry
			if err := decodeEntry(line, &prev); err == nil {
				if prev.Sequence > lastSeq {
					lastSeq = prev.Sequence
				}
				if prev.EntryHash != "" {
					lastHash = prev.EntryHash
				}
			}
		}
	}

	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	// Hash-chained protocol marker (not for 0.1.0 targets). Mirrors Python.
	if targetProtocol(revDir) != "0.1.0" {
		md := make(map[string]interface{}, len(metadata)+1)
		for k, v := range metadata {
			md[k] = v
		}
		md["wags_protocol"] = ProtocolVersion
		metadata = md
	}
	for _, f := range findings {
		if !validSeverity(f.Severity) {
			return nil, fmt.Errorf("invalid finding severity %q; must be one of P0, P1, P2, P3, N", f.Severity)
		}
	}
	_, hasRes := metadata["resolves"]
	_, hasSup := metadata["supersedes"]
	if hasRes || hasSup {
		prior, _ := readStream(streamPath)
		if errs := checkResolutionRefs(prior, metadata); len(errs) > 0 {
			return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
		}
	}

	// Convert []Finding to []map[string]interface{} for canonical (sorted-key) JSON hashing
	findingsMaps := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		findingsMaps = append(findingsMaps, map[string]interface{}{
			"id":             f.ID,
			"severity":       f.Severity,
			"surface":        f.Surface,
			"finding":        f.Finding,
			"evidence":       f.Evidence,
			"recommendation": f.Recommendation,
		})
	}

	entry := &StreamEntry{
		Sequence:  lastSeq + 1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ReviewID:  reviewID,
		Reviewer:  reviewerName,
		Phase:     phase,
		PrevHash:  lastHash,
		Findings:  findingsMaps,
		Verdict:   verdict,
		Metadata:  metadata,
	}
	if entry.Findings == nil {
		entry.Findings = []map[string]interface{}{}
	}

	if err := signEntry(entry, secretKey); err != nil {
		return nil, err
	}

	bytes, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(streamPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := f.Write(append(bytes, '\n')); err != nil {
		return nil, err
	}

	return entry, nil
}

func (ws *WagsWorkspace) TailReview(reviewID string) ([]StreamEntry, error) {
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	matches, err := filepath.Glob(filepath.Join(revDir, "*.jsonl"))
	if err != nil {
		return nil, err
	}

	var all []StreamEntry
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry StreamEntry
			if err := decodeEntry(line, &entry); err == nil {
				all = append(all, entry)
			}
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Timestamp == all[j].Timestamp {
			return all[i].Sequence < all[j].Sequence
		}
		return all[i].Timestamp < all[j].Timestamp
	})

	return all, nil
}

func targetProtocol(revDir string) string {
	var t map[string]interface{}
	if b, err := os.ReadFile(filepath.Join(revDir, "target.json")); err == nil {
		_ = json.Unmarshal(b, &t)
	}
	if v, ok := t["protocol_version"].(string); ok {
		return v
	}
	return ""
}

func registeredReviewers(revDir string) map[string]interface{} {
	reg := map[string]interface{}{}
	if b, err := os.ReadFile(filepath.Join(revDir, "reviewers.json")); err == nil {
		_ = json.Unmarshal(b, &reg)
	}
	return reg
}

// legacyAllStreams: count every stream only for protocol 0.1.0 targets with an
// empty/missing registry (wags-go 0.1.0 never populated reviewers.json).
func legacyAllStreams(revDir string) bool {
	return registryModeFor(revDir) == "legacy_all_streams"
}

// loadPrevConvergence returns ("absent"|"unparseable"|"present", data).
func loadPrevConvergence(revDir string) (string, map[string]interface{}) {
	b, err := os.ReadFile(filepath.Join(revDir, "converged.json"))
	if err != nil {
		return "absent", map[string]interface{}{}
	}
	var data map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil || data == nil {
		return "unparseable", map[string]interface{}{}
	}
	if a, ok := data["anchors"]; ok && a != nil {
		if _, isMap := a.(map[string]interface{}); !isMap {
			return "unparseable", map[string]interface{}{}
		}
	}
	return "present", data
}

// uses020Features lists 0.2.0-only features found in a review. Mirrors Python.
func uses020Features(revDir string) []string {
	found := []string{}
	matches, _ := filepath.Glob(filepath.Join(revDir, "*.jsonl"))
	sort.Strings(matches)
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".jsonl")
		ents, _ := readStream(m)
		for _, e := range ents {
			if e.Metadata == nil {
				continue
			}
			_, r := e.Metadata["resolves"]
			_, sp := e.Metadata["supersedes"]
			if r || sp {
				found = append(found, fmt.Sprintf("%s seq %d: resolves/supersedes", name, e.Sequence))
			}
			if wp, ok := e.Metadata["wags_protocol"]; ok && fmt.Sprintf("%v", wp) != "0.1.0" {
				found = append(found, fmt.Sprintf("%s seq %d: chained wags_protocol %v", name, e.Sequence, wp))
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(revDir)), "index.json")); err == nil {
		var idx map[string]interface{}
		if json.Unmarshal(b, &idx) == nil {
			if wpv, _ := idx["protocol_version"].(string); wpv != "" && wpv != "0.1.0" {
				found = append(found, "index.json workspace protocol_version "+wpv)
			}
			if rv, ok := idx["reviews"].(map[string]interface{}); ok {
				if r, ok := rv[filepath.Base(revDir)].(map[string]interface{}); ok {
					if rpv, _ := r["protocol_version"].(string); rpv != "" && rpv != "0.1.0" {
						found = append(found, "index.json review protocol_version "+rpv)
					}
				}
			}
		}
	}
	status, prev := loadPrevConvergence(revDir)
	if status == "present" {
		if ctx, ok := prev["anchor_context"].(map[string]interface{}); ok {
			if pv, _ := ctx["protocol_version"].(string); pv != "" && pv != "0.1.0" {
				found = append(found, "converged.json anchor_context protocol_version "+pv)
			}
			if rm, _ := ctx["registry_mode"].(string); rm == "registered" {
				found = append(found, "converged.json recorded registry_mode=registered")
			}
		}
	}
	return found
}

// registryModeFor: legacy count-all only for a 0.1.0 target with an empty registry,
// no 0.2.0 features and no previously recorded registered mode.
func registryModeFor(revDir string) string {
	if targetProtocol(revDir) != "0.1.0" || len(registeredReviewers(revDir)) > 0 {
		return "registered"
	}
	if st, _ := loadPrevConvergence(revDir); st == "unparseable" || len(uses020Features(revDir)) > 0 {
		return "registered"
	}
	return "legacy_all_streams"
}

func (ws *WagsWorkspace) VerifyReview(reviewID string, keys map[string]string) (bool, []string, error) {
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	if _, err := os.Stat(revDir); os.IsNotExist(err) {
		return false, nil, fmt.Errorf("review %s not found", reviewID)
	}
	matches, err := filepath.Glob(filepath.Join(revDir, "*.jsonl"))
	if err != nil {
		return false, nil, err
	}
	if len(matches) == 0 {
		return false, []string{"no reviewer streams found"}, nil
	}

	valid := true
	var errorsList []string
	legacyTarget := targetProtocol(revDir) == "0.1.0" && len(uses020Features(revDir)) == 0
	registered := registeredReviewers(revDir)
	legacyAll := registryModeFor(revDir) == "legacy_all_streams"

	for _, match := range matches {
		reviewer := strings.TrimSuffix(filepath.Base(match), ".jsonl")
		data, err := os.ReadFile(match)
		if err != nil {
			return false, nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		expectedPrev := GenesisHash
		var prior []StreamEntry
		seenCanonical := false

		for idx, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry StreamEntry
			if err := decodeEntry(line, &entry); err != nil {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: JSON parse error", reviewer, idx+1))
				continue
			}
			if entry.PrevHash != expectedPrev {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: PrevHash mismatch got %s, expected %s", reviewer, idx+1, entry.PrevHash, expectedPrev))
			}
			secret := ""
			if keys != nil {
				secret = keys[reviewer]
			}
			ok, msg := verifyEntryOpt(&entry, secret, legacyTarget && !seenCanonical)
			if ok && hashForm(&entry) == "canonical" {
				seenCanonical = true
			} else if !ok && legacyTarget && seenCanonical && hashForm(&entry) == "legacy" {
				msg = "legacy-form hash after a canonical-form entry is not allowed"
			}
			if !ok {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: %s", reviewer, idx+1, msg))
			}
			if entry.Sequence != len(prior)+1 {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: sequence %d out of order (expected %d)", reviewer, idx+1, entry.Sequence, len(prior)+1))
			}
			if entry.Reviewer != reviewer {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: reviewer '%s' does not match stream", reviewer, idx+1, entry.Reviewer))
			}
			for _, m := range checkResolutionRefs(prior, entry.Metadata) {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: %s", reviewer, idx+1, m))
			}
			prior = append(prior, entry)
			expectedPrev = entry.EntryHash
		}
		if _, ok := registered[reviewer]; len(prior) > 0 && !legacyAll && !ok {
			valid = false
			noun := "entries"
			if len(prior) == 1 {
				noun = "entry"
			}
			errorsList = append(errorsList, fmt.Sprintf("%s: stream '%s' has %d %s but reviewer is not registered in reviewers.json", reviewer, reviewer, len(prior), noun))
		}
	}
	return valid, errorsList, nil
}

// readStream reads one reviewer stream in file (append) order.
func readStream(path string) ([]StreamEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []StreamEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e StreamEntry
		if err := decodeEntry(line, &e); err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// stringList extracts a []string from a metadata value; ok=false if malformed.
func stringList(v interface{}) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]interface{})
	if !ok {
		if sa, ok2 := v.([]string); ok2 {
			return sa, true
		}
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// checkResolutionRefs validates metadata.resolves / metadata.supersedes against
// the reviewer's OWN earlier entries. Mirrors Python _check_resolution_refs.
func checkResolutionRefs(prior []StreamEntry, md map[string]interface{}) []string {
	var errs []string
	if md == nil {
		return nil
	}
	ids := map[string]bool{}
	hashes := map[string]bool{}
	for _, e := range prior {
		hashes[e.EntryHash] = true
		for _, f := range e.Findings {
			if id, ok := f["id"].(string); ok {
				ids[id] = true
			}
		}
	}
	if v, present := md["resolves"]; present && v == nil {
		errs = append(errs, "metadata.resolves must be a list of finding id strings")
	} else if res, ok := stringList(md["resolves"]); !ok {
		errs = append(errs, "metadata.resolves must be a list of finding id strings")
	} else if _, present := md["resolves"]; present && len(res) == 0 {
		errs = append(errs, "metadata.resolves must not be empty")
	} else {
		for _, id := range res {
			if !ids[id] {
				errs = append(errs, fmt.Sprintf("metadata.resolves references unknown finding '%s' (not in this reviewer's earlier entries)", id))
			}
		}
	}
	if v, present := md["supersedes"]; present && v == nil {
		errs = append(errs, "metadata.supersedes must be a list of entry_hash strings")
	} else if sup, ok := stringList(md["supersedes"]); !ok {
		errs = append(errs, "metadata.supersedes must be a list of entry_hash strings")
	} else if _, present := md["supersedes"]; present && len(sup) == 0 {
		errs = append(errs, "metadata.supersedes must not be empty")
	} else {
		for _, h := range sup {
			if !hashes[h] {
				errs = append(errs, fmt.Sprintf("metadata.supersedes references unknown entry '%s' (not an earlier entry in this reviewer's stream)", h))
			}
		}
	}
	return errs
}

func validSeverity(sev string) bool {
	switch strings.ToUpper(sev) {
	case "P0", "P1", "P2", "P3", "N":
		return true
	}
	return false
}

// streamState returns latest verdict, open findings, resolved findings.
// Entries are processed in sequence order; a resolving entry closes only
// finding instances raised in EARLIER entries, so an id re-raised after it
// was resolved is open again. Mirrors Python _stream_state.
func streamState(entries []StreamEntry) (string, []map[string]interface{}, []map[string]interface{}) {
	entries = append([]StreamEntry(nil), entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
	latest := ""
	type inst struct {
		hash     string
		f        map[string]interface{}
		resolved bool
	}
	var insts []*inst
	for idx, e := range entries {
		if e.Metadata != nil && len(checkResolutionRefs(entries[:idx], e.Metadata)) == 0 {
			res, _ := stringList(e.Metadata["resolves"])
			sup, _ := stringList(e.Metadata["supersedes"])
			ids := map[string]bool{}
			hs := map[string]bool{}
			for _, x := range res {
				ids[x] = true
			}
			for _, x := range sup {
				hs[x] = true
			}
			for _, in := range insts {
				id, _ := in.f["id"].(string)
				if ids[id] || hs[in.hash] {
					in.resolved = true
				}
			}
		}
		if e.Verdict != "" {
			latest = e.Verdict
		}
		for _, f := range e.Findings {
			insts = append(insts, &inst{hash: e.EntryHash, f: f})
		}
	}
	var open, resolved []map[string]interface{}
	for _, in := range insts {
		if in.resolved {
			resolved = append(resolved, in.f)
		} else {
			open = append(open, in.f)
		}
	}
	return latest, open, resolved
}

// ConvergeReview: latest verdict per reviewer + open findings only (protocol 0.2.0).
func (ws *WagsWorkspace) ConvergeReview(reviewID string) (map[string]interface{}, error) {
	return ws.ConvergeReviewOpts(reviewID, nil)
}

func filterContains(xs []string, sub string) []string {
	out := []string{}
	for _, x := range xs {
		if strings.Contains(x, sub) {
			out = append(out, x)
		}
	}
	return out
}

// MaxMinQuorum bounds min_quorum (same as Python MAX_MIN_QUORUM).
const MaxMinQuorum = 1000000

// ValidateMinQuorum: nil (default: all registered) or an integer in 1..MaxMinQuorum.
func ValidateMinQuorum(v *int) error {
	if v != nil && (*v < 1 || *v > MaxMinQuorum) {
		return fmt.Errorf("min_quorum must be a positive integer (1..%d); got %d", MaxMinQuorum, *v)
	}
	return nil
}

// ParseMinQuorum parses an explicitly supplied CLI value with the same rule and
// message as Python: ASCII digits only, 1..MaxMinQuorum. An empty string is rejected.
func ParseMinQuorum(text string) (*int, error) {
	bad := fmt.Errorf("min_quorum must be a positive integer (1..%d); got '%s'", MaxMinQuorum, text)
	if text == "" || len(text) > 7 {
		return nil, bad
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return nil, bad
		}
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > MaxMinQuorum {
		return nil, bad
	}
	return &n, nil
}

// ConvergeReviewOpts: minQuorum nil = every registered reviewer must vote; otherwise >= 1.
func (ws *WagsWorkspace) ConvergeReviewOpts(reviewID string, minQuorum *int) (map[string]interface{}, error) {
	if err := ValidateMinQuorum(minQuorum); err != nil {
		return nil, err
	}
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	targetBytes, err := os.ReadFile(filepath.Join(revDir, "target.json"))
	if err != nil {
		return nil, err
	}
	var targetManifest map[string]interface{}
	_ = json.Unmarshal(targetBytes, &targetManifest)

	matches, err := filepath.Glob(filepath.Join(revDir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	verifyOK, verrs, _ := ws.VerifyReview(reviewID, nil)
	registered := registeredReviewers(revDir)
	legacyAll := legacyAllStreams(revDir)
	registryMode := "registered"
	if legacyAll {
		registryMode = "legacy_all_streams"
	}

	// Anchors from the previous convergence (truncation / deletion / downgrade detection).
	anchorStatus, prev := loadPrevConvergence(revDir)
	prevAnchors := map[string]map[string]interface{}{}
	if am, ok := prev["anchors"].(map[string]interface{}); ok {
		for k, v := range am {
			if vm, ok := v.(map[string]interface{}); ok {
				prevAnchors[k] = vm
			}
		}
	}
	prevCtx, _ := prev["anchor_context"].(map[string]interface{})
	prevLost, _ := prev["anchor_lost"].(bool)
	targetProto := targetProtocol(revDir)
	anchorProblems := []string{}
	if anchorStatus == "unparseable" {
		anchorProblems = append(anchorProblems, "converged.json is unparseable; previous anchors lost")
	}
	if prevLost {
		anchorProblems = append(anchorProblems, "an earlier convergence found converged.json unparseable; operator must review")
	}
	prevRegistered := []string{}
	if prevCtx != nil {
		pv, _ := prevCtx["protocol_version"].(string)
		if pv != "" && pv != "0.1.0" && targetProto == "0.1.0" {
			anchorProblems = append(anchorProblems, fmt.Sprintf("protocol downgrade: anchored %s, target.json now %s", pv, targetProto))
		}
		prm, _ := prevCtx["registry_mode"].(string)
		if prm == "registered" && registryMode == "legacy_all_streams" {
			anchorProblems = append(anchorProblems, "registry mode changed from registered to legacy_all_streams")
		}
		if rl, ok := prevCtx["registered_reviewers"].([]interface{}); ok {
			gone := []string{}
			for _, x := range rl {
				if n, ok := x.(string); ok {
					prevRegistered = append(prevRegistered, n)
					if _, still := registered[n]; !still {
						gone = append(gone, n)
					}
				}
			}
			sort.Strings(gone)
			if len(gone) > 0 && prm == "registered" {
				anchorProblems = append(anchorProblems, "registered reviewer(s) disappeared from reviewers.json: "+strings.Join(gone, ", "))
			}
		}
	}
	if targetProto == "0.1.0" {
		feats := uses020Features(revDir)
		if len(feats) > 0 && len(registered) == 0 {
			anchorProblems = append(anchorProblems, "target.json says 0.1.0 but review uses 0.2.0 features: "+strings.Join(feats, "; "))
		} else if cw := filterContains(feats, "chained wags_protocol"); len(cw) > 0 {
			anchorProblems = append(anchorProblems, "protocol downgrade: target.json says 0.1.0 but hash-chained entries are "+strings.Join(cw, "; "))
		} else {
			rs := []string{}
			for _, x := range feats {
				if strings.Contains(x, "resolves/supersedes") {
					rs = append(rs, x)
				}
			}
			if len(rs) > 0 {
				anchorProblems = append(anchorProblems, "target.json says 0.1.0 but entries use resolves/supersedes (0.2.0): "+strings.Join(rs, "; "))
			}
		}
	}
	regressedStreams := []map[string]interface{}{}
	regressedNames := map[string]bool{}
	anchorNames := make([]string, 0, len(prevAnchors))
	for n := range prevAnchors {
		anchorNames = append(anchorNames, n)
	}
	sort.Strings(anchorNames)
	for _, name := range anchorNames {
		a := prevAnchors[name]
		seq := 0
		if n, ok := a["sequence"].(json.Number); ok {
			if v, err := n.Int64(); err == nil {
				seq = int(v)
			}
		}
		h, _ := a["entry_hash"].(string)
		ap := filepath.Join(revDir, name+".jsonl")
		reason := ""
		if _, err := os.Stat(ap); err != nil {
			reason = "stream deleted"
		} else {
			cur, _ := readStream(ap)
			bySeq := map[int]string{}
			for _, e := range cur {
				bySeq[e.Sequence] = e.EntryHash
			}
			_, isReg := registered[name]
			if len(cur) < seq {
				reason = fmt.Sprintf("stream shorter than anchor (%d < %d)", len(cur), seq)
			} else if bySeq[seq] != h {
				reason = fmt.Sprintf("anchored entry_hash missing at sequence %d", seq)
			} else if !legacyAll && !isReg {
				reason = "reviewer removed from reviewers.json"
			}
		}
		if reason != "" {
			regressedNames[name] = true
			regressedStreams = append(regressedStreams, map[string]interface{}{
				"reviewer": name, "anchor": map[string]interface{}{"sequence": seq, "entry_hash": h}, "reason": reason})
		}
	}
	invalidStreams := []map[string]interface{}{}
	unregisteredStreams := []string{}
	unknownSev := []map[string]interface{}{}
	allSeverityCounts := map[string]int{"P0": 0, "P1": 0, "P2": 0, "P3": 0, "N": 0}

	reviewerVerdicts := map[string]string{}
	severityCounts := map[string]int{"P0": 0, "P1": 0, "P2": 0, "P3": 0, "N": 0}
	blockingFindings := []map[string]interface{}{}
	openFindings := []map[string]interface{}{}
	resolvedFindings := []map[string]interface{}{}
	openP0, blockingP1 := 0, 0

	for _, m := range matches {
		reviewer := strings.TrimSuffix(filepath.Base(m), ".jsonl")
		var serrs []string
		for _, e := range verrs {
			if strings.HasPrefix(e, reviewer+" line ") || strings.HasPrefix(e, reviewer+": ") {
				serrs = append(serrs, e)
			}
		}
		if _, ok := registered[reviewer]; !ok && !legacyAll {
			unregisteredStreams = append(unregisteredStreams, reviewer)
			if len(serrs) > 0 { // has entries (or garbage): fail closed
				invalidStreams = append(invalidStreams, map[string]interface{}{"reviewer": reviewer, "errors": serrs})
			}
			continue
		}
		if len(serrs) > 0 {
			invalidStreams = append(invalidStreams, map[string]interface{}{"reviewer": reviewer, "errors": serrs})
			continue
		}
		entries, err := readStream(m)
		if err != nil {
			continue
		}
		for _, e := range entries {
			for _, f := range e.Findings {
				allSeverityCounts[strings.ToUpper(fmt.Sprintf("%v", f["severity"]))]++
			}
		}
		latest, open, resolved := streamState(entries)
		if latest != "" {
			reviewerVerdicts[reviewer] = latest
		}
		resolvedFindings = append(resolvedFindings, resolved...)
		for _, f := range open {
			openFindings = append(openFindings, f)
			sev := strings.ToUpper(fmt.Sprintf("%v", f["severity"]))
			if !validSeverity(sev) {
				unknownSev = append(unknownSev, f) // treated conservatively as P0
				sev = "P0"
			}
			severityCounts[sev]++
			if sev == "P0" {
				openP0++
				blockingFindings = append(blockingFindings, f)
			} else if sev == "P1" && strings.ToLower(latest) != "approve" {
				blockingP1++
				blockingFindings = append(blockingFindings, f)
			}
		}
	}

	totalReviewers := len(reviewerVerdicts)
	verdictCounts := map[string]int{"approve": 0, "request_changes": 0, "block": 0, "defer": 0}
	for _, v := range reviewerVerdicts {
		verdictCounts[strings.ToLower(v)]++
	}

	overallVerdict := "DEFER"
	rationale := "Insufficient quorum or inconclusive vote."

	quorumRequired := 0
	var quorumWarning interface{}
	if minQuorum == nil {
		if registryMode == "registered" {
			quorumRequired = len(registered)
		} else {
			quorumRequired = totalReviewers
		}
	} else {
		quorumRequired = *minQuorum
		if registryMode == "registered" && *minQuorum > len(registered) {
			quorumWarning = fmt.Sprintf("min_quorum %d exceeds the %d registered reviewer(s); quorum can never be met", *minQuorum, len(registered))
		}
	}
	quorumMet := totalReviewers > 0 && totalReviewers >= quorumRequired && quorumWarning == nil

	if len(anchorProblems) > 0 {
		overallVerdict = "BLOCK"
		rationale = "Anchor/protocol problem: " + strings.Join(anchorProblems, "; ")
	} else if len(regressedStreams) > 0 {
		names := []string{}
		for _, x := range regressedStreams {
			names = append(names, x["reviewer"].(string))
		}
		overallVerdict = "BLOCK"
		rationale = fmt.Sprintf("Regression: %d stream(s) lost entries or registration since the last convergence anchor (%s).", len(regressedStreams), strings.Join(names, ", "))
	} else if len(invalidStreams) > 0 {
		names := []string{}
		for _, x := range invalidStreams {
			names = append(names, x["reviewer"].(string))
		}
		overallVerdict = "BLOCK"
		rationale = fmt.Sprintf("Integrity failure: %d stream(s) failed verification (%s); excluded and review blocked.", len(invalidStreams), strings.Join(names, ", "))
	} else if openP0 > 0 || verdictCounts["block"] > 0 {
		overallVerdict = "BLOCK"
		rationale = fmt.Sprintf("Blocked by %d open P0 finding(s) or explicit block vote.", openP0)
	} else if blockingP1 > 0 || verdictCounts["request_changes"] > 0 {
		overallVerdict = "REQUEST_CHANGES"
		rationale = fmt.Sprintf("Changes required: %d blocking open P1 finding(s) or request_changes vote(s).", blockingP1)
	} else if quorumWarning != nil {
		overallVerdict = "DEFER"
		rationale = "Pending quorum: " + quorumWarning.(string)
	} else if !quorumMet {
		overallVerdict = "DEFER"
		rationale = fmt.Sprintf("Pending quorum: %d/%d required reviewers have voted (%d registered).", totalReviewers, quorumRequired, len(registered))
	} else if totalReviewers > 0 && float64(verdictCounts["approve"]) >= (float64(totalReviewers)/2.0) {
		overallVerdict = "APPROVE"
		rationale = fmt.Sprintf("Approved by majority (%d/%d) with 0 blockers.", verdictCounts["approve"], totalReviewers)
	}

	// New anchors; regressed streams keep their old anchor so the BLOCK persists.
	anchors := map[string]interface{}{}
	for n := range regressedNames {
		anchors[n] = prevAnchors[n]
	}
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".jsonl")
		if _, ok := registered[name]; regressedNames[name] || (!legacyAll && !ok) {
			continue
		}
		ents, _ := readStream(m)
		sort.SliceStable(ents, func(i, j int) bool { return ents[i].Sequence < ents[j].Sequence })
		if len(ents) > 0 {
			last := ents[len(ents)-1]
			anchors[name] = map[string]interface{}{"sequence": last.Sequence, "entry_hash": last.EntryHash}
		}
	}

	var anchorContext map[string]interface{}
	if prevCtx != nil && len(anchorProblems) > 0 {
		anchorContext = prevCtx
	} else {
		regs := []string{}
		for n := range registered {
			regs = append(regs, n)
		}
		if len(anchorProblems) > 0 {
			seen := map[string]bool{}
			for _, n := range regs {
				seen[n] = true
			}
			for _, n := range prevRegistered {
				if !seen[n] {
					regs = append(regs, n)
				}
			}
		}
		sort.Strings(regs)
		anchorContext = map[string]interface{}{"protocol_version": targetProto, "registry_mode": registryMode, "registered_reviewers": regs}
	}
	anchorLost := prevLost || anchorStatus == "unparseable"
	if anchorStatus == "unparseable" {
		anchors = map[string]interface{}{}
	}
	var mq interface{}
	if minQuorum != nil {
		mq = *minQuorum
	}
	if anchorStatus == "present" {
		if _, ok := prev["anchor_context"].(map[string]interface{}); !ok {
			anchorStatus = "present_no_context" // older converged.json (pre round-3)
		}
	}

	converged := map[string]interface{}{
		"protocol_version": ProtocolVersion,
		"review_id":        reviewID,
		"converged_at":     time.Now().UTC().Format(time.RFC3339),
		"target":           targetManifest["target"],
		"overall_verdict":  overallVerdict,
		"rationale":        rationale,
		"quorum_met":       quorumMet,
		"quorum":           map[string]interface{}{"required": quorumRequired, "voted": totalReviewers, "registered": len(registered), "min_quorum": mq, "warning": quorumWarning},
		"anchor_status":    anchorStatus,
		"anchor_problems":  anchorProblems,
		"anchor_context":   anchorContext,
		"anchor_lost":      anchorLost,
		"summary": map[string]interface{}{
			"total_reviewers":           totalReviewers,
			"verdicts":                  verdictCounts,
			"findings_by_severity":      allSeverityCounts,
			"open_findings_by_severity": severityCounts,
		},
		"invalid_streams":           invalidStreams,
		"unregistered_streams":      unregisteredStreams,
		"registry_empty":            len(registered) == 0,
		"registry_mode":             registryMode,
		"regressed_streams":         regressedStreams,
		"verify_valid":              verifyOK,
		"verify_scope":              "all stream files; invalid_streams lists the ones that failed (registered or unregistered-with-entries)",
		"anchors":                   anchors,
		"unknown_severity_findings": unknownSev,
		"blocking_findings":         blockingFindings,
		"open_findings":             openFindings,
		"resolved_findings":         resolvedFindings,
	}

	data, _ := json.MarshalIndent(converged, "", "  ")
	if err := atomicWriteFile(filepath.Join(revDir, "converged.json"), data); err != nil {
		return nil, fmt.Errorf("failed to write converged.json: %w", err)
	}

	return converged, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("wags CLI (Go implementation)")
		fmt.Println("Commands: init, add-reviewer, submit, tail, verify, converge")
		os.Exit(1)
	}

	ws, err := NewWagsWorkspace("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing workspace: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		initCmd := flag.NewFlagSet("init", flag.ExitOnError)
		target := initCmd.String("target", "", "Target file path")
		desc := initCmd.String("desc", "", "Description")
		initiator := initCmd.String("initiator", "go-agent", "Initiator name")
		_ = initCmd.Parse(os.Args[2:])
		if *target == "" {
			fmt.Println("Usage: wags init -target <path>")
			os.Exit(1)
		}
		res, err := ws.InitReview(*target, "code", *desc, *initiator, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[wags-go] Initialized review %s\n", res["review_id"])

	case "verify":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wags verify <review_id>")
			os.Exit(1)
		}
		ok, errs, err := ws.VerifyReview(os.Args[2], nil)
		if err != nil || !ok {
			fmt.Printf("[wags-go] Verification FAILED: %v\n", errs)
			os.Exit(1)
		}
		fmt.Printf("[wags-go] Review %s integrity: VERIFIED\n", os.Args[2])

	case "converge":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wags converge <review_id>")
			os.Exit(1)
		}
		convCmd := flag.NewFlagSet("converge", flag.ExitOnError)
		minQ := convCmd.String("min-quorum", "", "Minimum reviewers with a verdict before APPROVE, integer >= 1 (default: all registered)")
		_ = convCmd.Parse(os.Args[3:])
		var mq *int
		provided := false
		convCmd.Visit(func(fl *flag.Flag) {
			if fl.Name == "min-quorum" {
				provided = true
			}
		})
		if provided { // an explicitly supplied value (even '') must validate
			var perr error
			mq, perr = ParseMinQuorum(*minQ)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", perr)
				os.Exit(2)
			}
		}
		conv, err := ws.ConvergeReviewOpts(os.Args[2], mq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[wags-go] Converged: %s (%s)\n", conv["overall_verdict"], conv["rationale"])

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
	}
}
