package output

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

type StdoutNDJSONWriter struct {
	mu     sync.Mutex
	writer *bufio.Writer
}

func NewStdoutNDJSONWriter() *StdoutNDJSONWriter {
	return &StdoutNDJSONWriter{
		writer: bufio.NewWriter(os.Stdout),
	}
}

func (w *StdoutNDJSONWriter) WriteResult(result *ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *StdoutNDJSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Flush()
}
