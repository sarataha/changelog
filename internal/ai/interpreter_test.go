package ai

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sarataha/changelog/internal/rawcollector"
)

func TestLogInterpreter_buildPrompt(t *testing.T) {
	interpreter := NewLogInterpreter("", "")
	
	testLogs := []rawcollector.RawLogEntry{
		{
			Timestamp: time.Date(2025, 8, 31, 14, 30, 0, 0, time.UTC),
			Source:    "auditd",
			Raw:       `type=USER_CMD msg=audit(1756639200.000:123): pid=1234 uid=501 cmd=746565 exe="/usr/bin/sudo"`,
		},
		{
			Timestamp: time.Date(2025, 8, 31, 14, 30, 5, 0, time.UTC),
			Source:    "journalctl",
			Raw:       `Aug 31 14:30:05 server systemd: nginx.service: Started`,
		},
	}
	
	prompt := interpreter.buildPrompt(testLogs)
	
	// Check prompt contains expected elements
	expectedElements := []string{
		"[auditd]",
		"[journalctl]", 
		"human-readable timeline",
		"WHO did WHAT",
		"cause-effect relationships",
	}
	
	for _, element := range expectedElements {
		if !strings.Contains(prompt, element) {
			t.Errorf("Prompt missing element: %s", element)
		}
	}
}

func TestLogInterpreter_InterpretLogs_MockServer(t *testing.T) {
	// Create mock Ollama server
	mockResponse := `14:30:00 - sara executed file operation
14:30:05 - nginx service started

=== CORRELATION DETECTED ===
Root cause: User command → Service restart`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("Expected /api/generate, got %s", r.URL.Path)
		}
		
		response := map[string]interface{}{
			"response": mockResponse,
			"done":     true,
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		writeJSON(w, response)
	}))
	defer server.Close()
	
	interpreter := NewLogInterpreter(server.URL, "test-model")
	
	testLogs := []rawcollector.RawLogEntry{
		{
			Timestamp: time.Now(),
			Source:    "auditd", 
			Raw:       "test log entry",
		},
	}
	
	result, err := interpreter.InterpretLogs(testLogs)
	if err != nil {
		t.Fatalf("InterpretLogs failed: %v", err)
	}
	
	if result != mockResponse {
		t.Errorf("Expected %q, got %q", mockResponse, result)
	}
}

func TestNewLogInterpreter_Defaults(t *testing.T) {
	interpreter := NewLogInterpreter("", "")
	
	if interpreter.ollamaURL != "http://localhost:11434" {
		t.Errorf("Expected default URL http://localhost:11434, got %s", interpreter.ollamaURL)
	}
	
	if interpreter.model != "llama3.2" {
		t.Errorf("Expected default model llama3.2, got %s", interpreter.model)
	}
}

func TestLogInterpreter_InterpretLogs_EmptyLogs(t *testing.T) {
	interpreter := NewLogInterpreter("http://fake-url", "test-model")
	
	emptyLogs := []rawcollector.RawLogEntry{}
	
	// Should handle empty logs gracefully
	prompt := interpreter.buildPrompt(emptyLogs)
	if len(prompt) < 100 {
		t.Error("Prompt should still contain instructions even with no logs")
	}
}

// Helper functions
func containsAll(text string, substrings []string) bool {
	for _, substr := range substrings {
		if !strings.Contains(text, substr) {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	// Simple JSON writing for tests - escape newlines
	response := strings.ReplaceAll(data.(map[string]interface{})["response"].(string), "\n", "\\n")
	w.Write([]byte(`{"response":"` + response + `","done":true}`))
}