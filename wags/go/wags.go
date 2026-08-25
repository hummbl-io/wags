// Package main implements wags v0.1.0 - polyglot air-gappable multi-agent peer review protocol.
// 100% Go standard library (zero external dependencies).
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ProtocolVersion = "0.1.0"
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

func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func computeEntryHash(entry *StreamEntry) (string, error) {
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

	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return computeSHA256(bytes), nil
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
	expectedHash, err := computeEntryHash(entry)
	if err != nil {
		return false, fmt.Sprintf("Hash calculation error: %v", err)
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
		_ = os.WriteFile(indexFile, data, 0644)
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
	if err := os.WriteFile(filepath.Join(revDir, "target.json"), data, 0644); err != nil {
		return nil, err
	}
	_ = os.WriteFile(filepath.Join(revDir, "reviewers.json"), []byte("{}"), 0644)

	return manifest, nil
}

func (ws *WagsWorkspace) RegisterReviewer(reviewID, reviewerName, secretKey, role string) error {
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	if _, err := os.Stat(revDir); os.IsNotExist(err) {
		return fmt.Errorf("review %s not found", reviewID)
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
			if err := json.Unmarshal([]byte(line), &prev); err == nil {
				if prev.Sequence > lastSeq {
					lastSeq = prev.Sequence
				}
				if prev.EntryHash != "" {
					lastHash = prev.EntryHash
				}
			}
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
		Metadata:  map[string]interface{}{},
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
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
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

	for _, match := range matches {
		reviewer := strings.TrimSuffix(filepath.Base(match), ".jsonl")
		data, err := os.ReadFile(match)
		if err != nil {
			return false, nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		expectedPrev := GenesisHash

		for idx, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry StreamEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
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
			ok, msg := verifyEntry(&entry, secret)
			if !ok {
				valid = false
				errorsList = append(errorsList, fmt.Sprintf("%s line %d: %s", reviewer, idx+1, msg))
			}
			expectedPrev = entry.EntryHash
		}
	}
	return valid, errorsList, nil
}

func (ws *WagsWorkspace) ConvergeReview(reviewID string) (map[string]interface{}, error) {
	revDir := filepath.Join(ws.ReviewsDir, reviewID)
	targetBytes, err := os.ReadFile(filepath.Join(revDir, "target.json"))
	if err != nil {
		return nil, err
	}
	var targetManifest map[string]interface{}
	_ = json.Unmarshal(targetBytes, &targetManifest)

	entries, err := ws.TailReview(reviewID)
	if err != nil {
		return nil, err
	}

	reviewerVerdicts := map[string]string{}
	severityCounts := map[string]int{"P0": 0, "P1": 0, "P2": 0, "P3": 0, "N": 0}
	var blockingFindings []map[string]interface{}

	for _, entry := range entries {
		if entry.Verdict != "" {
			reviewerVerdicts[entry.Reviewer] = entry.Verdict
		}
		for _, f := range entry.Findings {
			sev := strings.ToUpper(fmt.Sprintf("%v", f["severity"]))
			severityCounts[sev]++
			if sev == "P0" || (sev == "P1" && entry.Verdict == "block") {
				blockingFindings = append(blockingFindings, f)
			}
		}
	}

	totalReviewers := len(reviewerVerdicts)
	verdictCounts := map[string]int{"approve": 0, "request_changes": 0, "block": 0, "defer": 0}
	for _, v := range reviewerVerdicts {
		nv := strings.ToLower(v)
		verdictCounts[nv]++
	}

	overallVerdict := "DEFER"
	rationale := "Insufficient quorum or inconclusive vote."

	if severityCounts["P0"] > 0 || verdictCounts["block"] > 0 {
		overallVerdict = "BLOCK"
		rationale = fmt.Sprintf("Blocked by %d P0 critical finding(s) or explicit block vote.", severityCounts["P0"])
	} else if severityCounts["P1"] > 0 || verdictCounts["request_changes"] > 0 {
		overallVerdict = "REQUEST_CHANGES"
		rationale = fmt.Sprintf("Changes required: %d P1 finding(s) or request_changes vote(s).", severityCounts["P1"])
	} else if totalReviewers > 0 && float64(verdictCounts["approve"]) >= (float64(totalReviewers)/2.0) {
		overallVerdict = "APPROVE"
		rationale = fmt.Sprintf("Approved by majority (%d/%d) with 0 blockers.", verdictCounts["approve"], totalReviewers)
	}

	converged := map[string]interface{}{
		"protocol_version":  ProtocolVersion,
		"review_id":         reviewID,
		"converged_at":      time.Now().UTC().Format(time.RFC3339),
		"target":            targetManifest["target"],
		"overall_verdict":   overallVerdict,
		"rationale":         rationale,
		"quorum_met":        totalReviewers > 0,
		"summary": map[string]interface{}{
			"total_reviewers":      totalReviewers,
			"verdicts":             verdictCounts,
			"findings_by_severity": severityCounts,
		},
		"blocking_findings": blockingFindings,
	}

	data, _ := json.MarshalIndent(converged, "", "  ")
	_ = os.WriteFile(filepath.Join(revDir, "converged.json"), data, 0644)

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
		conv, err := ws.ConvergeReview(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[wags-go] Converged: %s (%s)\n", conv["overall_verdict"], conv["rationale"])

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
	}
}
