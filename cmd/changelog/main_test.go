package main

import (
	"testing"
	"time"
)

func TestParseTimeRange(t *testing.T) {
	tests := []struct {
		name         string
		incidentTime string
		window       string
		wantErr      bool
	}{
		{
			name:         "valid time and window",
			incidentTime: "14:30:00",
			window:       "10m",
			wantErr:      false,
		},
		{
			name:         "empty incident time uses current time",
			incidentTime: "",
			window:       "1h",
			wantErr:      false,
		},
		{
			name:         "RFC3339 format",
			incidentTime: "2025-08-31T14:30:00Z",
			window:       "5m",
			wantErr:      false,
		},
		{
			name:         "invalid window format",
			incidentTime: "14:30:00",
			window:       "invalid",
			wantErr:      true,
		},
		{
			name:         "invalid time format",
			incidentTime: "25:70:99",
			window:       "10m",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeRange, err := parseTimeRange(tt.incidentTime, tt.window)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Verify time range is properly configured
			if timeRange.Start.After(timeRange.End) {
				t.Error("start time should be before end time")
			}
			
			// Verify window duration
			if tt.window == "10m" {
				expectedDuration := 10 * time.Minute
				actualDuration := timeRange.End.Sub(timeRange.Start)
				if actualDuration != expectedDuration {
					t.Errorf("expected duration %v, got %v", expectedDuration, actualDuration)
				}
			}
		})
	}
}

func TestParseIncidentTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		checkHour int
	}{
		{
			name:      "time only format",
			input:     "14:30:45",
			wantErr:   false,
			checkHour: 14,
		},
		{
			name:    "RFC3339 format",
			input:   "2025-08-31T14:30:45Z",
			wantErr: false,
			checkHour: 14,
		},
		{
			name:    "invalid format",
			input:   "not-a-time",
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
				return
			}
			
			if result.Hour() != tt.checkHour {
				t.Errorf("expected hour %d, got %d", tt.checkHour, result.Hour())
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
				return
			}
			
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}