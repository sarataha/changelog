package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
		model = "llama3.2:1b"
	}
	
	return &LogInterpreter{
		ollamaURL: ollamaURL,
		model:     model,
	}
}

// ChatMessage represents a chat message
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OllamaRequest represents the OpenAI-compatible API request format
type OllamaRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// ChatChoice represents a choice in the response
type ChatChoice struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

// OllamaResponse represents the OpenAI-compatible API response format
type OllamaResponse struct {
	Choices []ChatChoice `json:"choices"`
}

// InterpretLogs converts raw logs to human-readable correlation timeline
func (li *LogInterpreter) InterpretLogs(rawLogs []rawcollector.RawLogEntry) (string, error) {
	if len(rawLogs) == 0 {
		return "No events found in the specified time window.", nil
	}
	
	// Limit logs to prevent timeout
	if len(rawLogs) > 2 {
		rawLogs = rawLogs[:2]
	}
	
	fmt.Printf("[DEBUG] Building prompt for %d events\n", len(rawLogs))
	prompt := li.buildPrompt(rawLogs)
	// Escape newlines for JSON
	prompt = strings.ReplaceAll(prompt, "\n", " ")
	
	fmt.Printf("[DEBUG] Creating request to %s with model %s\n", li.ollamaURL, li.model)
	reqBody := OllamaRequest{
		Model: li.model,
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		Stream: false,
	}
	
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	fmt.Printf("[DEBUG] Request size: %d bytes\n", len(jsonData))
	
	// Create request with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	fmt.Printf("[DEBUG] Sending request to Ollama...\n")
	req, err := http.NewRequestWithContext(ctx, "POST", li.ollamaURL+"/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Ollama API: %w", err)
	}
	defer resp.Body.Close()
	fmt.Printf("[DEBUG] Got response with status: %d\n", resp.StatusCode)
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama API returned status %d", resp.StatusCode)
	}
	
	fmt.Printf("[DEBUG] Reading response body...\n")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	fmt.Printf("[DEBUG] Response size: %d bytes\n", len(body))
	
	fmt.Printf("[DEBUG] Parsing JSON response...\n")
	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	
	if len(ollamaResp.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}
	
	fmt.Printf("[DEBUG] AI interpretation successful\n")
	return ollamaResp.Choices[0].Message.Content, nil
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