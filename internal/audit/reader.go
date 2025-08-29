package audit

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// FileLogReader implements LogReader for reading from audit log files
type FileLogReader struct {
	file    *os.File
	scanner *bufio.Scanner
}

// NewFileLogReader creates a new file log reader
func NewFileLogReader(filePath string) (LogReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &FileLogReader{
		file:    file,
		scanner: bufio.NewScanner(file),
	}, nil
}

// ReadEvent reads the next raw line from the file
func (f *FileLogReader) ReadEvent() (*AuditEvent, error) {
	if f.scanner.Scan() {
		line := f.scanner.Text()
		return &AuditEvent{Raw: line}, nil
	}

	if err := f.scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return nil, io.EOF
}

// Close closes the file reader
func (f *FileLogReader) Close() error {
	return f.file.Close()
}