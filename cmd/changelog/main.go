package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/sarataha/changelog/internal/audit"
	"github.com/sarataha/changelog/internal/output"
	"github.com/sarataha/changelog/internal/parser"
)

func main() {
	auditLogPath := "/var/log/audit/audit.log"
	if len(os.Args) > 1 {
		auditLogPath = os.Args[1]
	}

	fmt.Printf("=== Reading audit log: %s ===\n", auditLogPath)

	reader, err := audit.NewFileLogReader(auditLogPath)
	if err != nil {
		log.Fatalf("Failed to open audit log: %v", err)
	}
	defer reader.Close()

	auditParser := parser.NewAuditdParser()
	userCmdInterpreter := parser.NewUserCommandInterpreter()
	syscallInterpreter := parser.NewSyscallInterpreter()
	formatter := output.NewSimpleFormatter()

	count := 0
	for {
		rawEvent, err := reader.ReadEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading event: %v", err)
			continue
		}

		event, err := auditParser.ParseLine(rawEvent.Raw)
		if err != nil {
			continue
		}

		var action *audit.SystemAction
		switch event.Type {
		case "USER_CMD":
			action, err = userCmdInterpreter.Interpret(event)
		case "SYSCALL":
			action, err = syscallInterpreter.Interpret(event)
		default:
			continue
		}

		if err != nil {
			continue
		}

		fmt.Println(formatter.Format(action))
		count++
	}

	fmt.Printf("\n=== Processed %d events ===\n", count)
}