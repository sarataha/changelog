package parser

import (
	"testing"
)

func TestUserResolver_GetUsername(t *testing.T) {
	resolver := NewUserResolver()

	tests := []struct {
		name     string
		uid      string
		expected string
	}{
		{
			name:     "root user",
			uid:      "0",
			expected: "root",
		},
		{
			name:     "regular user by UID",
			uid:      "1000",
			expected: "1000", // fallback to UID if user not found
		},
		{
			name:     "invalid UID string",
			uid:      "invalid",
			expected: "invalid", // fallback to original string
		},
		{
			name:     "empty UID",
			uid:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.GetUsername(tt.uid)
			if result != tt.expected {
				t.Errorf("GetUsername(%s) = %v, want %v", tt.uid, result, tt.expected)
			}
		})
	}
}

func TestUserResolver_GetUsernameByUID(t *testing.T) {
	resolver := NewUserResolver()

	tests := []struct {
		name     string
		uid      int
		expected string
	}{
		{
			name:     "root UID 0",
			uid:      0,
			expected: "root",
		},
		{
			name:     "non-existent user",
			uid:      9999,
			expected: "9999", // fallback to UID string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.GetUsernameByUID(tt.uid)
			if result != tt.expected {
				t.Errorf("GetUsernameByUID(%d) = %v, want %v", tt.uid, result, tt.expected)
			}
		})
	}
}

func TestUserResolver_Caching(t *testing.T) {
	resolver := NewUserResolver()
	
	// First lookup
	result1 := resolver.GetUsername("0")
	
	// Second lookup should use cache
	result2 := resolver.GetUsername("0")
	
	if result1 != result2 {
		t.Errorf("Caching failed: first lookup %v != second lookup %v", result1, result2)
	}
	
	if result1 != "root" {
		t.Errorf("Expected root, got %v", result1)
	}
}

func TestUserResolver_ParsePasswdLine(t *testing.T) {
	resolver := NewUserResolver()

	tests := []struct {
		name     string
		line     string
		uid      int
		username string
		valid    bool
	}{
		{
			name:     "valid passwd line",
			line:     "root:x:0:0:root:/root:/bin/bash",
			uid:      0,
			username: "root",
			valid:    true,
		},
		{
			name:     "regular user",
			line:     "john:x:1000:1000:John Doe:/home/john:/bin/bash",
			uid:      1000,
			username: "john",
			valid:    true,
		},
		{
			name:  "invalid line - too few fields",
			line:  "invalid:line",
			valid: false,
		},
		{
			name:  "invalid UID",
			line:  "user:x:invalid:1000:User:/home/user:/bin/bash",
			valid: false,
		},
		{
			name:  "empty line",
			line:  "",
			valid: false,
		},
		{
			name:  "comment line",
			line:  "# this is a comment",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, username, err := resolver.parsePasswdLine(tt.line)
			
			if tt.valid {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
					return
				}
				
				if uid != tt.uid {
					t.Errorf("uid mismatch: got %v, want %v", uid, tt.uid)
				}
				
				if username != tt.username {
					t.Errorf("username mismatch: got %v, want %v", username, tt.username)
				}
			} else {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			}
		})
	}
}