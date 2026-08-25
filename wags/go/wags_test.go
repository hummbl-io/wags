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
