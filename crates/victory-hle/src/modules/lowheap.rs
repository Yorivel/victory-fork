//! The C runtime's heap for title code below 128 GiB (`VICTORY_LOW_HEAP=1`).
//!
//! Title images import `malloc` and its kin from `api-ms-win-crt-heap`, which the host's
//! runtime serves from the process heap, above 2^40 on the host. The console's heap lies in
//! the title's own address space, low enough for the 40-bit addresses translated shaders
//! follow through title memory by address (`victory_shader::emit::SLOT_MEMORY`, whose
//! directory covers the first 128 GiB). The ray-tracing structure builder keeps its build
//! descriptions in such blocks and hands them to its programs: above the directory every
//! access through a pointer read out of memory reads 0 and drops its store, silently (fork
//! #16: 83% of the builder's dispatches named such memory).
//!
//! With the switch, these blocks come from a heap made in a region reserved and committed
//! below 128 GiB. A pointer from anywhere else (a block the host's runtime made itself, say
//! by `_strdup`, freed by the title) goes back to the host's runtime. Without the switch, or
//! when the region cannot be had or is full, everything is the host's as before.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::System::Memory::{
    HeapAlloc, HeapFree, HeapReAlloc, HeapSize, MEM_ADDRESS_REQUIREMENTS, MEM_EXTENDED_PARAMETER, MEM_LARGE_PAGES,
    MEM_RESERVE, MemExtendedParameterAddressRequirements, PAGE_READWRITE, VirtualAlloc as HostVirtualAlloc, VirtualAlloc2,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::{HleExport, HleModule, hle_export};

/// Where the region starts (120 GiB) and its size (1 GiB): under the directory's last
/// entry, which is never filled, and above the title's own memory. (`RtlCreateHeap` refuses
/// a caller's region of 4 GiB; 1 GiB is taken, reserved only, the heap committing as it
/// grows.)
const BASE: usize = 0x1E_0000_0000;
const SIZE: usize = 1 << 30;
/// `MEM_WRITE_WATCH`.
const MEM_WRITE_WATCH: u32 = 0x0020_0000;
/// `HEAP_GROWABLE`: the heap commits pages of the reserved region as it needs them.
const GROWABLE: u32 = 0x2;
/// `HEAP_ZERO_MEMORY`.
const ZERO: u32 = 0x8;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlCreateHeap(
        flags: u32,
        base: *mut c_void,
        reserve: usize,
        commit: usize,
        lock: *mut c_void,
        parameters: *mut c_void,
    ) -> *mut c_void;
}

unsafe extern "C" {
    #[link_name = "malloc"]
    fn host_malloc(size: usize) -> *mut c_void;
    #[link_name = "calloc"]
    fn host_calloc(n: usize, size: usize) -> *mut c_void;
    #[link_name = "realloc"]
    fn host_realloc(at: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn host_free(at: *mut c_void);
    #[link_name = "_aligned_offset_malloc"]
    fn host_aligned_offset_malloc(size: usize, align: usize, offset: usize) -> *mut c_void;
    #[link_name = "_aligned_free"]
    fn host_aligned_free(at: *mut c_void);
}

/// The low heap, once made; `None`: off or not to be had.
fn heap() -> Option<usize> {
    static HEAP: OnceLock<Option<usize>> = OnceLock::new();
    *HEAP.get_or_init(|| {
        if !std::env::var_os("VICTORY_LOW_HEAP").is_some_and(|v| v == "1") {
            return None;
        }
        // SAFETY: a fixed region of our own, reserved, then given to a heap of its own.
        unsafe {
            let at = HostVirtualAlloc(BASE as *const c_void, SIZE, MEM_RESERVE, PAGE_READWRITE);
            if at as usize != BASE {
                tracing::warn!(base = format_args!("{BASE:#x}"), "low heap: the region could not be had; the title's heap stays the host's");
                return None;
            }
            let heap = RtlCreateHeap(GROWABLE, at, SIZE, 1 << 16, std::ptr::null_mut(), std::ptr::null_mut());
            if heap.is_null() {
                tracing::warn!("low heap: RtlCreateHeap failed; the title's heap stays the host's");
                return None;
            }
            tracing::info!(base = format_args!("{BASE:#x}"), gib = SIZE >> 30, "low heap: the title's malloc is served below 128 GiB (VICTORY_LOW_HEAP=1)");
            Some(heap as usize)
        }
    })
}

fn ours(at: *mut c_void) -> bool {
    (BASE..BASE + SIZE).contains(&(at as usize))
}

fn handle(h: usize) -> windows_sys::Win32::Foundation::HANDLE {
    h as windows_sys::Win32::Foundation::HANDLE
}

fn full() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| tracing::warn!("low heap: full; further blocks come from the host's heap"));
}

pub extern "C" fn malloc(size: usize) -> *mut c_void {
    if let Some(h) = heap() {
        // SAFETY: our heap.
        let at = unsafe { HeapAlloc(handle(h), 0, size.max(1)) };
        if !at.is_null() {
            return at;
        }
        full();
    }
    // SAFETY: the host's runtime.
    unsafe { host_malloc(size) }
}

pub extern "C" fn calloc(n: usize, size: usize) -> *mut c_void {
    if let Some(h) = heap() {
        let Some(bytes) = n.checked_mul(size) else {
            return std::ptr::null_mut();
        };
        // SAFETY: our heap.
        let at = unsafe { HeapAlloc(handle(h), ZERO, bytes.max(1)) };
        if !at.is_null() {
            return at;
        }
        full();
    }
    // SAFETY: the host's runtime.
    unsafe { host_calloc(n, size) }
}

pub extern "C" fn free(at: *mut c_void) {
    if at.is_null() {
        return;
    }
    match heap() {
        // SAFETY: a block of our heap.
        Some(h) if ours(at) => unsafe {
            HeapFree(handle(h), 0, at);
        },
        // SAFETY: a block of the host's runtime.
        _ => unsafe { host_free(at) },
    }
}

pub extern "C" fn realloc(at: *mut c_void, size: usize) -> *mut c_void {
    if at.is_null() {
        return malloc(size);
    }
    if size == 0 {
        free(at);
        return std::ptr::null_mut();
    }
    match heap() {
        Some(h) if ours(at) => {
            // SAFETY: a block of our heap.
            let moved = unsafe { HeapReAlloc(handle(h), 0, at, size) };
            if !moved.is_null() {
                return moved;
            }
            // Full: to the host's heap, copied.
            // SAFETY: a block of our heap; the new block holds `size` bytes.
            unsafe {
                let old = HeapSize(handle(h), 0, at);
                let new = host_malloc(size);
                if !new.is_null() {
                    std::ptr::copy_nonoverlapping(at.cast::<u8>(), new.cast::<u8>(), old.min(size));
                    HeapFree(handle(h), 0, at);
                }
                new
            }
        }
        // SAFETY: a block of the host's runtime.
        _ => unsafe { host_realloc(at, size) },
    }
}

/// `_aligned_offset_malloc` as the runtime does it: the block from `malloc`, the pointer to
/// it stored in the machine word just below the aligned address (rounded down to a word).
pub extern "C" fn _aligned_offset_malloc(size: usize, align: usize, offset: usize) -> *mut c_void {
    if heap().is_none() {
        // SAFETY: the host's runtime.
        return unsafe { host_aligned_offset_malloc(size, align, offset) };
    }
    let word = size_of::<usize>();
    let align = align.max(word);
    if !align.is_power_of_two() || (offset != 0 && offset >= size) {
        return std::ptr::null_mut();
    }
    // Room for the alignment and two words below the user's address: the stored pointer
    // goes in the word below that address rounded down to a word.
    let Some(total) = size.checked_add(align + 2 * word) else {
        return std::ptr::null_mut();
    };
    let block = malloc(total) as usize;
    if block == 0 {
        return std::ptr::null_mut();
    }
    // `user + offset` aligned, at least two words past the block's start.
    let user = (block + 2 * word + offset).next_multiple_of(align) - offset;
    // SAFETY: inside the block: the word written lies at or above `block`, and
    // `user + size` at or below `block + total`.
    unsafe { ((user & !(word - 1)) as *mut usize).sub(1).write(block) };
    user as *mut c_void
}

pub extern "C" fn _aligned_malloc(size: usize, align: usize) -> *mut c_void {
    _aligned_offset_malloc(size, align, 0)
}

pub extern "C" fn _aligned_free(at: *mut c_void) {
    if at.is_null() {
        return;
    }
    // SAFETY: an aligned block of either runtime stores its block's start in the word below.
    let block = unsafe { ((at as usize & !(size_of::<usize>() - 1)) as *const *mut c_void).sub(1).read() };
    if heap().is_some() && ours(block) {
        free(block);
    } else {
        // SAFETY: an aligned block of the host's runtime.
        unsafe { host_aligned_free(at) }
    }
}

/// `VirtualAlloc` for title code (`VICTORY_LOW_HEAP=1`): a call that leaves the address to
/// the system gets one between 68 GiB (past the title's own memory) and the low heap's
/// region (120 GiB), as on the console, whose system places it in the title's address
/// space. On the host it lay above 2^40, past the 40-bit directory: the ray-tracing
/// builder's per-build memory came from here (private regions of 70 KB to 15 MB). With
/// write watch, as `XMemVirtualAlloc`'s reservations have, so the GPU side copies only the
/// pages written. A call with an address, or one the range cannot take, is the host's.
#[allow(non_snake_case)]
pub extern "system" fn VirtualAlloc(base: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void {
    if base.is_null() && heap().is_some() {
        let mut requirements = MEM_ADDRESS_REQUIREMENTS {
            LowestStartingAddress: 0x11_0000_0000usize as *mut c_void,
            HighestEndingAddress: (BASE - 1) as *mut c_void,
            Alignment: 0,
        };
        let mut parameter = MEM_EXTENDED_PARAMETER::default();
        parameter.Anonymous1._bitfield = MemExtendedParameterAddressRequirements as u64;
        parameter.Anonymous2.Pointer = (&raw mut requirements).cast();
        let watch = if kind & MEM_LARGE_PAGES == 0 { MEM_WRITE_WATCH } else { 0 };
        // SAFETY: the title's arguments; the parameter points at `requirements`, which
        // outlives the call.
        let at = unsafe {
            VirtualAlloc2(GetCurrentProcess(), std::ptr::null_mut(), size, kind | MEM_RESERVE | watch, protect, &mut parameter, 1)
        };
        if !at.is_null() {
            return at;
        }
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| tracing::warn!(size, kind = format_args!("{kind:#x}"), "low heap: a VirtualAlloc did not fit below 120 GiB; the host placed it"));
    }
    // SAFETY: the title's own arguments.
    unsafe { HostVirtualAlloc(base, size, kind, protect) }
}

pub(crate) fn module_virtual() -> HleModule {
    HleModule {
        name: "lowvirtual",
        dlls: &["api-ms-win-core-memory-*"],
        exports: vec![hle_export!(VirtualAlloc)],
    }
}

pub(crate) fn module() -> HleModule {
    HleModule {
        name: "lowheap",
        dlls: &["api-ms-win-crt-heap-*"],
        exports: vec![
            hle_export!(malloc),
            hle_export!(calloc),
            hle_export!(free),
            hle_export!(realloc),
            HleExport { name: "_malloc_base", address: malloc as *const () as usize },
            HleExport { name: "_calloc_base", address: calloc as *const () as usize },
            HleExport { name: "_free_base", address: free as *const () as usize },
            HleExport { name: "_realloc_base", address: realloc as *const () as usize },
            hle_export!(_aligned_malloc),
            hle_export!(_aligned_offset_malloc),
            hle_export!(_aligned_free),
        ],
    }
}
