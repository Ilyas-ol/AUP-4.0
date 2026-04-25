#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::arch::is_x86_feature_detected;
#[cfg(target_arch = "x86")]
use std::arch::x86::__cpuid;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;

#[derive(Debug, thiserror::Error)]
pub enum KernelBridgeError {
    #[error("debugger detected")]
    DebuggerDetected,
    #[error("injection detected")]
    InjectionDetected,
    #[error("vm or sandbox detected")]
    VmDetected,
    #[error("operation not implemented")]
    NotImplemented,
}

#[derive(Debug, Clone, Copy)]
pub enum ExecutionRoute {
    RealPath,
    DecoyPath,
}

pub trait ThreatSignalProvider: Send + Sync {
    fn debugger_present(&self) -> bool;
    fn injection_detected(&self) -> bool;
    fn vm_detected(&self) -> bool;
    fn risk_signal(&self) -> u8;
}

pub struct NullThreatSignalProvider;

impl ThreatSignalProvider for NullThreatSignalProvider {
    fn debugger_present(&self) -> bool {
        false
    }

    fn injection_detected(&self) -> bool {
        false
    }

    fn vm_detected(&self) -> bool {
        false
    }

    fn risk_signal(&self) -> u8 {
        0
    }
}

pub struct SystemThreatSignalProvider;

impl SystemThreatSignalProvider {
    pub fn new() -> Self {
        Self
    }
}

impl ThreatSignalProvider for SystemThreatSignalProvider {
    fn debugger_present(&self) -> bool {
        debugger_present_system()
    }

    fn injection_detected(&self) -> bool {
        injection_detected_system()
    }

    fn vm_detected(&self) -> bool {
        vm_present_system()
    }

    fn risk_signal(&self) -> u8 {
        let mut score = 0u8;
        if self.debugger_present() {
            score = score.saturating_add(3);
        }
        if self.vm_detected() {
            score = score.saturating_add(2);
        }
        if self.injection_detected() {
            score = score.saturating_add(1);
        }
        score
    }
}

pub struct KernelBridge {
    provider: Box<dyn ThreatSignalProvider>,
}

impl KernelBridge {
    pub fn new() -> Self {
        Self::with_provider(default_provider())
    }

    pub fn with_provider(provider: Box<dyn ThreatSignalProvider>) -> Self {
        Self { provider }
    }

    pub fn check_debugger(&self) -> Result<(), KernelBridgeError> {
        if self.provider.debugger_present() {
            Err(KernelBridgeError::DebuggerDetected)
        } else {
            Ok(())
        }
    }

    pub fn block_injection(&self) -> Result<(), KernelBridgeError> {
        if self.provider.injection_detected() {
            Err(KernelBridgeError::InjectionDetected)
        } else {
            Ok(())
        }
    }

    pub fn detect_vm(&self) -> Result<(), KernelBridgeError> {
        if self.provider.vm_detected() {
            Err(KernelBridgeError::VmDetected)
        } else {
            Ok(())
        }
    }

    pub fn select_route(&self, risk_signal: u8) -> ExecutionRoute {
        let combined_risk = risk_signal.saturating_add(self.provider.risk_signal());
        if combined_risk == 0 {
            ExecutionRoute::RealPath
        } else {
            ExecutionRoute::DecoyPath
        }
    }
}

fn default_provider() -> Box<dyn ThreatSignalProvider> {
    #[cfg(target_os = "windows")]
    {
        Box::new(SystemThreatSignalProvider::new())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Box::new(NullThreatSignalProvider)
    }
}

#[cfg(target_os = "windows")]
mod windows_ffi {
    use std::ffi::c_void;

    extern "system" {
        pub fn IsDebuggerPresent() -> i32;
        pub fn CheckRemoteDebuggerPresent(
            hProcess: *mut c_void,
            pbDebuggerPresent: *mut i32,
        ) -> i32;
        pub fn GetCurrentProcess() -> *mut c_void;
    }
}

#[cfg(target_os = "windows")]
fn debugger_present_system() -> bool {
    // SAFETY: Calling read-only Windows process introspection APIs with valid parameters.
    unsafe {
        if windows_ffi::IsDebuggerPresent() != 0 {
            return true;
        }

        let mut present = 0i32;
        let ok = windows_ffi::CheckRemoteDebuggerPresent(
            windows_ffi::GetCurrentProcess(),
            &mut present as *mut i32,
        );
        ok != 0 && present != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn debugger_present_system() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn injection_detected_system() -> bool {
    module_scan_for_injection_markers()
}

#[cfg(not(target_os = "windows"))]
fn injection_detected_system() -> bool {
    false
}

fn vm_present_system() -> bool {
    hypervisor_cpuid_flag()
}

fn hypervisor_cpuid_flag() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if !is_x86_feature_detected!("sse") {
            return false;
        }

        let leaf1 = __cpuid(1);
        const HYPERVISOR_BIT: u32 = 1 << 31;
        (leaf1.ecx & HYPERVISOR_BIT) != 0
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
mod module_scan_windows {
    use std::ffi::c_void;

    pub const TH32CS_SNAPMODULE: u32 = 0x00000008;
    pub const TH32CS_SNAPMODULE32: u32 = 0x00000010;

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct MODULEENTRY32W {
        pub dwSize: u32,
        pub th32ModuleID: u32,
        pub th32ProcessID: u32,
        pub GlblcntUsage: u32,
        pub ProccntUsage: u32,
        pub modBaseAddr: *mut u8,
        pub modBaseSize: u32,
        pub hModule: *mut c_void,
        pub szModule: [u16; 256],
        pub szExePath: [u16; 260],
    }

    extern "system" {
        pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut c_void;
        pub fn Module32FirstW(hSnapshot: *mut c_void, lpme: *mut MODULEENTRY32W) -> i32;
        pub fn Module32NextW(hSnapshot: *mut c_void, lpme: *mut MODULEENTRY32W) -> i32;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
        pub fn GetCurrentProcessId() -> u32;
    }
}

#[cfg(target_os = "windows")]
fn module_scan_for_injection_markers() -> bool {
    use module_scan_windows::{
        CloseHandle, CreateToolhelp32Snapshot, GetCurrentProcessId, Module32FirstW, Module32NextW,
        MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };
    use std::ffi::c_void;

    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;

    // SAFETY: Win32 snapshot and module enumeration APIs are called with valid process id and structs.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(flags, GetCurrentProcessId());
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return false;
        }

        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry as *mut MODULEENTRY32W) == 0 {
            let _ = CloseHandle(snapshot);
            return false;
        }

        loop {
            let module = module_name_lowercase(&entry.szModule);
            if is_suspicious_injection_module(&module) {
                let _ = CloseHandle(snapshot);
                return true;
            }

            if Module32NextW(snapshot, &mut entry as *mut MODULEENTRY32W) == 0 {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
        false
    }
}

#[cfg(target_os = "windows")]
fn module_name_lowercase(raw: &[u16]) -> String {
    let end = raw.iter().position(|&ch| ch == 0).unwrap_or(raw.len());
    String::from_utf16_lossy(&raw[..end]).to_ascii_lowercase()
}

#[cfg(target_os = "windows")]
fn is_suspicious_injection_module(module_name: &str) -> bool {
    const MARKERS: &[&str] = &[
        "frida",
        "x64dbg",
        "ollydbg",
        "scylla",
        "cheatengine",
        "dnspy",
        "ida",
    ];

    MARKERS.iter().any(|marker| module_name.contains(marker))
}
