package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Entry struct {
	TS         time.Time         `json:"ts"`
	Subject    string            `json:"subject"`
	Email      string            `json:"email,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	Instance   string            `json:"instance,omitempty"`
	Action     string            `json:"action"`
	Args       map[string]string `json:"args,omitempty"`
	Result     string            `json:"result"`
	HTTPStatus int               `json:"http_status,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type Logger struct {
	mu sync.Mutex
	f  *os.File
}

func New(path string) (*Logger, error) {
	if path == "" {
		return &Logger{f: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{f: f}, nil
}

func (l *Logger) Log(e Entry) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

func (l *Logger) Close() error {
	if l.f == os.Stdout {
		return nil
	}
	return l.f.Close()
}
