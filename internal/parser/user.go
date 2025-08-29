package parser

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// UserResolver maps UIDs to usernames with caching
type UserResolver struct {
	cache  map[int]string
	mutex  sync.RWMutex
	loaded bool
}

// NewUserResolver creates a new user resolver with caching
func NewUserResolver() *UserResolver {
	return &UserResolver{
		cache: make(map[int]string),
	}
}

// GetUsername converts a UID string to username, with fallback to UID
func (u *UserResolver) GetUsername(uidStr string) string {
	if uidStr == "" {
		return ""
	}

	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return uidStr
	}

	return u.GetUsernameByUID(uid)
}

// GetUsernameByUID converts a UID int to username, with fallback to UID string
func (u *UserResolver) GetUsernameByUID(uid int) string {
	u.mutex.RLock()
	if username, exists := u.cache[uid]; exists {
		u.mutex.RUnlock()
		return username
	}
	u.mutex.RUnlock()

	if !u.loaded {
		u.loadPasswdFile()
	}

	u.mutex.RLock()
	if username, exists := u.cache[uid]; exists {
		u.mutex.RUnlock()
		return username
	}
	u.mutex.RUnlock()

	return strconv.Itoa(uid)
}

// loadPasswdFile reads /etc/passwd and populates the cache
func (u *UserResolver) loadPasswdFile() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.loaded {
		return
	}

	file, err := os.Open("/etc/passwd")
	if err != nil {
		u.loaded = true
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		uid, username, err := u.parsePasswdLine(line)
		if err == nil {
			u.cache[uid] = username
		}
	}

	u.loaded = true
}

// parsePasswdLine parses a line from /etc/passwd
func (u *UserResolver) parsePasswdLine(line string) (int, string, error) {
	line = strings.TrimSpace(line)
	
	if line == "" || strings.HasPrefix(line, "#") {
		return 0, "", fmt.Errorf("invalid line")
	}

	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return 0, "", fmt.Errorf("insufficient fields")
	}

	username := fields[0]
	uidStr := fields[2]

	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid UID: %w", err)
	}

	return uid, username, nil
}