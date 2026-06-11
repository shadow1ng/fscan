//go:build web

package common

// WebMode Web版本始终为true
const WebMode = true

// WebPort 不再使用，端口由 main_web.go 的 -port 参数控制
var WebPort = 0
