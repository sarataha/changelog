package main

import (
	"fmt"
	"log"

	"github.com/sarataha/changelog/internal/parser"
)

func main() {
	// Sample auditd log lines for testing
	sampleLines := []string{
		`type=SYSCALL msg=audit(1640995200.000:123): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 comm="vim" uid=1000`,
		`type=PATH msg=audit(1640995200.123:124): item=0 name="/etc/nginx/nginx.conf" inode=12345 mode=0100644`,
		`type=EXECVE msg=audit(1640995300.456:125): argc=3 a0="systemctl" a1="restart" a2="nginx"`,
	}

	parser := parser.NewAuditdParser()

	fmt.Println("=== Phase 0.1: Basic auditd log parsing ===")
	
	for i, line := range sampleLines {
		fmt.Printf("\n--- Sample %d ---\n", i+1)
		fmt.Printf("Input: %s\n", line)
		
		event, err := parser.ParseLine(line)
		if err != nil {
			log.Printf("Error parsing line: %v", err)
			continue
		}

		fmt.Printf("Parsed Event:\n")
		fmt.Printf("  Timestamp: %s\n", event.Timestamp.Format("2006-01-02 15:04:05.000"))
		fmt.Printf("  Type: %s\n", event.Type)
		fmt.Printf("  Fields:\n")
		for key, value := range event.Fields {
			fmt.Printf("    %s = %s\n", key, value)
		}
	}
}