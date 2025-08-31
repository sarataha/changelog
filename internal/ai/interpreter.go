package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sarataha/changelog/internal/rawcollector"
)

// LogInterpreter handles AI-powered log interpretation via Ollama
type LogInterpreter struct {
	ollamaURL string
	model     string
}

// NewLogInterpreter creates a new log interpreter
func NewLogInterpreter(ollamaURL, model string) *LogInterpreter {
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	
	return &LogInterpreter{
		ollamaURL: ollamaURL,
		model:     model,
	}
}

// OllamaRequest represents the API request format
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse represents the API response format
type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// InterpretLogs converts raw logs to human-readable correlation timeline
func (li *LogInterpreter) InterpretLogs(rawLogs []rawcollector.RawLogEntry) (string, error) {
	if len(rawLogs) == 0 {
		return "No events found in the specified time window.", nil
	}
	
	prompt := li.buildPrompt(rawLogs)
	
	reqBody := OllamaRequest{
		Model:  li.model,
		Prompt: prompt,
		Stream: false,
	}
	
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	
	resp, err := http.Post(li.ollamaURL+"/api/generate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to call Ollama API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama API returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	
	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	
	return ollamaResp.Response, nil
}

func (li *LogInterpreter) buildPrompt(rawLogs []rawcollector.RawLogEntry) string {
	var logLines []string
	
	for _, entry := range rawLogs {
		timestamp := entry.Timestamp.Format("15:04:05")
		logLines = append(logLines, fmt.Sprintf("%s [%s] %s", timestamp, entry.Source, entry.Raw))
	}
	
	prompt := fmt.Sprintf(`You are a Linux system administrator analyzing audit logs for incident response. Convert these raw system logs into a human-readable timeline showing WHO did WHAT and WHY.

Focus on:
- File changes and their consequences  
- Service restarts and configuration changes
- User actions and automated system responses
- cause-effect relationships (X caused Y)

Raw logs:
%s

Please provide:
1. A clean timeline in this format:
   HH:MM:SS - WHO did WHAT (brief description)

2. Any correlations you detect:
   === CORRELATION DETECTED ===
   Root cause: X → led to Y → resulted in Z

Keep it concise and focused on actionable insights for incident response.`, strings.Join(logLines, "\n"))

	return prompt
}