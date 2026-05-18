package common

import "sync"

// ResultCallback 扫描结果回调函数类型
type ResultCallback func(result interface{})

var (
	resultCallback ResultCallback
	callbackMu     sync.RWMutex
)

// SetResultCallback 设置结果回调函数（Web模式使用）
func SetResultCallback(cb ResultCallback) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	resultCallback = cb
}

// ReplaceResultCallback temporarily replaces the result callback and returns a
// restore function. This is useful for embedded callers that need to collect
// structured results without permanently stealing the callback from another
// subsystem.
func ReplaceResultCallback(cb ResultCallback) func() {
	callbackMu.Lock()
	previous := resultCallback
	resultCallback = cb
	callbackMu.Unlock()

	return func() {
		callbackMu.Lock()
		resultCallback = previous
		callbackMu.Unlock()
	}
}

// NotifyResult 通知结果给回调函数
func NotifyResult(result interface{}) {
	callbackMu.RLock()
	cb := resultCallback
	callbackMu.RUnlock()

	if cb != nil {
		cb(result)
	}
}

// ClearResultCallback 清除结果回调函数
func ClearResultCallback() {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	resultCallback = nil
}
