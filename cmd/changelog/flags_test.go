package main

import (
	"testing"
	"time"
)

func TestParseIncidentTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Time
		wantErr  bool
	}{
		{
			name:     "RFC3339 format",
			input:    "2025-08-29T14:32:00Z",
			expected: time.Date(2025, 8, 29, 14, 32, 0, 0, time.UTC),
			wantErr:  false,
		},
		{
			name:     "simple time format",
			input:    "14:32:00",
			expected: time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 14, 32, 0, 0, time.Local),
			wantErr:  false,
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIncidentTime(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.name == "simple time format" {
				// For time-only format, just check hour/minute/second
				if result.Hour() != tt.expected.Hour() || 
				   result.Minute() != tt.expected.Minute() || 
				   result.Second() != tt.expected.Second() {
					t.Errorf("time mismatch: got %v, want %v", result, tt.expected)
				}
			} else {
				if !result.Equal(tt.expected) {
					t.Errorf("time mismatch: got %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "minutes",
			input:    "10m",
			expected: 10 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "hours",
			input:    "2h",
			expected: 2 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "seconds",
			input:    "30s",
			expected: 30 * time.Second,
			wantErr:  false,
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseWindow(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("duration mismatch: got %v, want %v", result, tt.expected)
			}
		})
	}
}