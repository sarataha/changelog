package main

import (
	"fmt"
	"log"

	"github.com/sarataha/changelog/internal/parser"
)

func main() {
	sampleLines := []string{
		`type=SYSCALL msg=audit(1640995200.000:123): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 comm="vim" uid=1000`,
		`type=SYSCALL msg=audit(1640995201.000:124): arch=c000003e syscall=1 success=yes exit=10 comm="vim" uid=1000`,
		`type=SYSCALL msg=audit(1640995202.000:125): arch=c000003e syscall=87 success=yes exit=0 comm="rm" uid=0`,
	}

	auditParser := parser.NewAuditdParser()
	syscallInterpreter := parser.NewSyscallInterpreter()

	fmt.Println("=== Phase 0.2: Syscall Interpretation ===")
	
	for i, line := range sampleLines {
		fmt.Printf("\n--- Sample %d ---\n", i+1)
		fmt.Printf("Input: %s\n", line)
		
		event, err := auditParser.ParseLine(line)
		if err != nil {
			log.Printf("Error parsing line: %v", err)
			continue
		}

		if event.Type == "SYSCALL" {
			action, err := syscallInterpreter.Interpret(event)
			if err != nil {
				log.Printf("Error interpreting syscall: %v", err)
				continue
			}

			fmt.Printf("Interpreted Action:\n")
			fmt.Printf("  %s user=%s action=%s process=%s\n", 
				action.Timestamp, action.User, action.Action, action.Process)
		}
	}
}