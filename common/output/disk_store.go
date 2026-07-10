package output

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var storedResultTypes = [...]ResultType{TypeHost, TypePort, TypeService, TypeVuln}

type diskResultStore struct {
	mu          sync.Mutex
	db          *bolt.DB
	writeTx     *bolt.Tx
	path        string
	closed      bool
	pendingSync int
	lastSync    time.Time
}

func newDiskResultStore(outputPath string) (*diskResultStore, error) {
	dir := filepath.Dir(outputPath)
	base := filepath.Base(outputPath)
	temp, err := os.CreateTemp(dir, "."+base+".store-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create result store: %w", err)
	}
	path := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close result store placeholder: %w", err)
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout:      time.Second,
		NoSync:       true,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("open result store: %w", err)
	}

	store := &diskResultStore{db: db, path: path, lastSync: time.Now()}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, resultType := range storedResultTypes {
			if _, err := tx.CreateBucketIfNotExists(recordsBucketName(resultType)); err != nil {
				return err
			}
			if _, err := tx.CreateBucketIfNotExists(seenBucketName(resultType)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("initialize result store: %w", err)
	}
	if err := db.Sync(); err != nil {
		_ = db.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync result store schema: %w", err)
	}
	return store, nil
}

func recordsBucketName(resultType ResultType) []byte {
	return []byte("records:" + string(resultType))
}

func seenBucketName(resultType ResultType) []byte {
	return []byte("seen:" + string(resultType))
}

func isStoredResultType(resultType ResultType) bool {
	switch resultType {
	case TypeHost, TypePort, TypeService, TypeVuln:
		return true
	default:
		return false
	}
}

func sequenceKey(sequence uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, sequence)
	return key
}

func (s *diskResultStore) Add(result *ScanResult) error {
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}
	if !isStoredResultType(result.Type) {
		return nil
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return fmt.Errorf("result store is closed")
	}

	if s.writeTx == nil {
		s.writeTx, err = s.db.Begin(true)
		if err != nil {
			return fmt.Errorf("begin result store transaction: %w", err)
		}
	}
	changed := false
	err = func(tx *bolt.Tx) error {
		records := tx.Bucket(recordsBucketName(result.Type))
		seen := tx.Bucket(seenBucketName(result.Type))
		if records == nil || seen == nil {
			return fmt.Errorf("result store bucket is missing for %s", result.Type)
		}

		key := append([]byte{1}, []byte(resultKey(result))...)
		if existingSequence := seen.Get(key); existingSequence != nil {
			if result.Type != TypeService {
				return nil
			}
			existingData := records.Get(existingSequence)
			if existingData == nil {
				return fmt.Errorf("service index points to a missing record")
			}
			var existing, incoming ScanResult
			if err := json.Unmarshal(existingData, &existing); err != nil {
				return fmt.Errorf("decode stored service: %w", err)
			}
			if err := json.Unmarshal(encoded, &incoming); err != nil {
				return fmt.Errorf("decode incoming service: %w", err)
			}
			mergeResultDetails(&existing, &incoming)
			selected := &existing
			if resultCompleteness(&incoming) > resultCompleteness(&existing) {
				selected = &incoming
			}
			merged, err := json.Marshal(selected)
			if err != nil {
				return fmt.Errorf("encode merged service: %w", err)
			}
			changed = true
			return records.Put(existingSequence, merged)
		}

		sequence, err := records.NextSequence()
		if err != nil {
			return err
		}
		sequenceBytes := sequenceKey(sequence)
		if err := records.Put(sequenceBytes, encoded); err != nil {
			return err
		}
		if err := seen.Put(key, sequenceBytes); err != nil {
			return err
		}
		changed = true
		return nil
	}(s.writeTx)
	if err != nil {
		_ = s.writeTx.Rollback()
		s.writeTx = nil
		return fmt.Errorf("store result: %w", err)
	}
	if !changed {
		if s.pendingSync > 0 && time.Since(s.lastSync) >= realtimeSyncInterval {
			return s.flushLocked(true)
		}
		return nil
	}
	s.pendingSync++
	if s.pendingSync >= realtimeSyncBatchSize || time.Since(s.lastSync) >= realtimeSyncInterval {
		return s.flushLocked(true)
	}
	return nil
}

func (s *diskResultStore) ForEach(resultType ResultType, fn func(*ScanResult) error) error {
	if fn == nil {
		return fmt.Errorf("result callback cannot be nil")
	}
	if !isStoredResultType(resultType) {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return fmt.Errorf("result store is closed")
	}
	if err := s.flushLocked(false); err != nil {
		return err
	}

	return s.db.View(func(tx *bolt.Tx) error {
		records := tx.Bucket(recordsBucketName(resultType))
		if records == nil {
			return nil
		}
		return records.ForEach(func(_, value []byte) error {
			var result ScanResult
			if err := json.Unmarshal(value, &result); err != nil {
				return fmt.Errorf("decode %s result: %w", resultType, err)
			}
			return fn(&result)
		})
	})
}

func (s *diskResultStore) Summary() (hosts, ports, services, vulns int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return 0, 0, 0, 0, fmt.Errorf("result store is closed")
	}
	if err := s.flushLocked(false); err != nil {
		return 0, 0, 0, 0, err
	}

	counts := make(map[ResultType]int, len(storedResultTypes))
	err = s.db.View(func(tx *bolt.Tx) error {
		for _, resultType := range storedResultTypes {
			bucket := tx.Bucket(recordsBucketName(resultType))
			if bucket != nil {
				counts[resultType] = bucket.Stats().KeyN
			}
		}
		return nil
	})
	return counts[TypeHost], counts[TypePort], counts[TypeService], counts[TypeVuln], err
}

func (s *diskResultStore) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return nil
	}
	return s.flushLocked(true)
}

func (s *diskResultStore) flushLocked(syncToDisk bool) error {
	if s.writeTx != nil {
		if err := s.writeTx.Commit(); err != nil {
			s.writeTx = nil
			return fmt.Errorf("commit result store: %w", err)
		}
		s.writeTx = nil
	}
	if syncToDisk {
		if err := s.db.Sync(); err != nil {
			return fmt.Errorf("sync result store: %w", err)
		}
		s.pendingSync = 0
		s.lastSync = time.Now()
	}
	return nil
}

func (s *diskResultStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var firstErr error
	if s.db != nil {
		if err := s.flushLocked(true); err != nil {
			firstErr = err
		}
		if err := s.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.closed = true
	return firstErr
}

func (s *diskResultStore) Remove() error {
	if s == nil || s.path == "" {
		return nil
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *diskResultStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}
