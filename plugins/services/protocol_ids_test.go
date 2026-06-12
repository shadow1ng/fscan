package services

import (
	"sync"
	"testing"
)

func TestProtocolIDsAreConcurrentSafe(t *testing.T) {
	const workers = 64
	const perWorker = 64

	tests := []struct {
		name string
		next func() uint32
	}{
		{"mongodb", nextRequestID},
		{"kafka", func() uint32 { return uint32(nextKafkaCorrelationID()) }},
		{"cassandra", func() uint32 { return uint32(nextCQLStreamID()) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			values := make(chan uint32, workers*perWorker)
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < perWorker; j++ {
						values <- tt.next()
					}
				}()
			}
			wg.Wait()
			close(values)

			seen := make(map[uint32]struct{}, workers*perWorker)
			for value := range values {
				if _, ok := seen[value]; ok {
					t.Fatalf("duplicate protocol id %d", value)
				}
				seen[value] = struct{}{}
			}
		})
	}
}
