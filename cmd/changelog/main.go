package main

import (
	"fmt"

	"github.com/sarataha/changelog/internal/output"
	"github.com/sarataha/changelog/internal/parser"
)

func main() {
	fmt.Println("=== Phase 0: Complete Demo ===")
	fmt.Println("Demo with sample data:")
	
	sampleLines := []string{
		`type=SYSCALL msg=audit(1640995200.000:123): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 comm="vim" uid=1000`,
		`type=SYSCALL msg=audit(1640995201.000:124): arch=c000003e syscall=1 success=yes exit=10 comm="vim" uid=1000`,
		`type=SYSCALL msg=audit(1640995202.000:125): arch=c000003e syscall=87 success=yes exit=0 comm="rm" uid=0`,
	}

	auditParser := parser.NewAuditdParser()
	syscallInterpreter := parser.NewSyscallInterpreter()
	formatter := output.NewSimpleFormatter()
	
	for _, line := range sampleLines {
		event, err := auditParser.ParseLine(line)
		if err != nil {
			continue
		}

		if event.Type == "SYSCALL" {
			action, err := syscallInterpreter.Interpret(event)
			if err != nil {
				continue
			}

			fmt.Println(formatter.Format(action))
		}
	}
}