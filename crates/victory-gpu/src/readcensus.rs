//! Read census of shader writes (`VICTORY_READ_CENSUS=1`, diagnostics only).
//!
//! Every byte shaders write is fetched back into title memory after the
//! submission (the copy-back), whether or not the title's processor ever
//! reads it. This counts how much of it the title does touch: each 4 KiB
//! page a copy-back wrote is given `PAGE_GUARD`, and a guard hit on it is
//! counted, once, as a read or a write by the title or as an access of the
//! layer's own (the faulting instruction in `victory.exe`), then let go on.
//! A page the copy-back writes again before anything touched it counts as
//! rewritten unread. The kernel's reads and writes (`host::read`,
//! `host::write_mapped`) would fail on a guard instead of faulting, so
//! those take the guards off first ([`disarm`]).
//!
//! shortcut: a guard is set from what `VirtualQuery` said a moment before;
//! a protection change by the write guards (`crate::watch`) between the two
//! calls is lost. A title call into the kernel on a guarded page (a file
//! read into it) fails. Measurement only: never on by default.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

const PAGE: usize = 4096;
/// Pages of the 40-bit title address space.
const PAGES: usize = 1 << 28;

/// Whether the census runs.
pub(crate) fn on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = std::env::var_os("VICTORY_READ_CENSUS").is_some_and(|v| v == "1");
        if on {
            // SAFETY: a plain registration of a handler that lives forever.
            unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler(1, Some(on_guard));
            }
            tracing::warn!("VICTORY_READ_CENSUS: copied-back pages are guarded to count what the title reads (slower)");
        }
        on
    })
}

/// One bit per page: guarded by the census and not touched since.
fn bits() -> &'static [AtomicU64] {
    static BITS: OnceLock<Box<[AtomicU64]>> = OnceLock::new();
    BITS.get_or_init(|| (0..PAGES / 64).map(|_| AtomicU64::new(0)).collect())
}

/// One bit per page the census ever guarded: a guard hit there that
/// [`bits`] no longer holds (arming or disarming on another thread at that
/// moment) is still the census's, and is let go on uncounted.
fn ever() -> &'static [AtomicU64] {
    static EVER: OnceLock<Box<[AtomicU64]>> = OnceLock::new();
    EVER.get_or_init(|| (0..PAGES / 64).map(|_| AtomicU64::new(0)).collect())
}

/// Pages armed, touched by a title read, by a title write, by the layer
/// (a fault in `victory.exe` or a kernel access of the layer), and
/// rewritten by a copy-back untouched.
/// Then the layer's touches split by who read (v2): the copy that copied
/// the page back (its refresh or its next merge), another copy, a texture,
/// and a reader no tag names.
static COUNT: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
const ARMED: usize = 0;
const TITLE_READ: usize = 1;
const TITLE_WRITE: usize = 2;
const HOST: usize = 3;
const AGAIN: usize = 4;
const SAME: usize = 5;
const OTHER: usize = 6;
const TEX: usize = 7;
const UNTAGGED: usize = 8;

/// Who on this thread reads or writes title memory now ([`tag`]).
pub(crate) const COPY: u8 = 1;
pub(crate) const MERGE: u8 = 2;
pub(crate) const TEXTURE: u8 = 3;
thread_local! {
    static READER: std::cell::Cell<(u8, u64)> = const { std::cell::Cell::new((0, 0)) };
}

/// Names this thread's reader until the result is dropped: a copy's
/// refresh (`COPY`, its id), a copy-back merge (`MERGE`, its id; pages it
/// writes are that copy's), a texture refresh (`TEXTURE`).
pub(crate) fn tag(kind: u8, id: u64) -> Tag {
    Tag(READER.with(|r| r.replace((kind, id))))
}

pub(crate) struct Tag((u8, u64));
impl Drop for Tag {
    fn drop(&mut self) {
        READER.with(|r| r.set(self.0));
    }
}

/// The copy whose copy-back guarded each page.
fn owners() -> &'static std::sync::Mutex<std::collections::HashMap<usize, u64>> {
    static OWNERS: OnceLock<std::sync::Mutex<std::collections::HashMap<usize, u64>>> = OnceLock::new();
    OWNERS.get_or_init(Default::default)
}

/// A touch of the layer's at `page`, counted by its reader.
fn layer_touch(page: usize) {
    COUNT[HOST].fetch_add(1, Relaxed);
    let (kind, id) = READER.with(std::cell::Cell::get);
    let owner = owners().lock().unwrap_or_else(|e| e.into_inner()).get(&page).copied();
    let which = match kind {
        COPY | MERGE if owner == Some(id) => SAME,
        COPY | MERGE => OTHER,
        TEXTURE => TEX,
        _ => UNTAGGED,
    };
    COUNT[which].fetch_add(1, Relaxed);
}
/// Guard hits on census pages caught between a bit and its guard.
static RACES: AtomicU64 = AtomicU64::new(0);
/// The first title instructions that read a guarded page.
static FIRST_RIPS: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];

fn take(page: usize) -> bool {
    if page >= PAGES {
        return false;
    }
    let bit = 1u64 << (page % 64);
    bits()[page / 64].fetch_and(!bit, Relaxed) & bit != 0
}

/// `victory.exe`'s image: `(start, end)`.
fn exe() -> (usize, usize) {
    static EXE: OnceLock<(usize, usize)> = OnceLock::new();
    *EXE.get_or_init(|| {
        // SAFETY: the process's own image, mapped for its life; its headers
        // are read as the loader laid them out.
        unsafe {
            let base = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null()) as usize;
            let nt = base + (*((base + 0x3c) as *const u32)) as usize;
            let size = *((nt + 24 + 56) as *const u32) as usize;
            (base, base + size)
        }
    })
}

unsafe extern "system" fn on_guard(p: *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) -> i32 {
    const GUARD: i32 = 0x8000_0001_u32 as i32;
    const CONTINUE_EXECUTION: i32 = -1;
    const CONTINUE_SEARCH: i32 = 0;
    // SAFETY: the system passes a valid record.
    let r = unsafe { &*(*p).ExceptionRecord };
    if r.ExceptionCode != GUARD || r.NumberParameters < 2 {
        return CONTINUE_SEARCH;
    }
    let address = r.ExceptionInformation[1];
    let page = address / PAGE;
    if !take(page) {
        if page < PAGES && ever()[page / 64].load(Relaxed) & (1u64 << (page % 64)) != 0 {
            RACES.fetch_add(1, Relaxed);
            return CONTINUE_EXECUTION;
        }
        return CONTINUE_SEARCH;
    }
    // The guard is gone with the fault: the access goes on when retried.
    let rip = r.ExceptionAddress as usize;
    let (start, end) = exe();
    // The layer's: its own code, or a thread a tag names (in a system
    // library the layer called).
    if (start..end).contains(&rip) || READER.with(std::cell::Cell::get).0 != 0 {
        layer_touch(page);
    } else if r.ExceptionInformation[0] == 1 {
        COUNT[TITLE_WRITE].fetch_add(1, Relaxed);
    } else {
        let n = COUNT[TITLE_READ].fetch_add(1, Relaxed) as usize;
        if n < FIRST_RIPS.len() {
            FIRST_RIPS[n].store(rip, Relaxed);
        }
    }
    CONTINUE_EXECUTION
}

/// Before the layer's kernel access to `[at, at + len)`: guards the census
/// set there come off. `again`: a copy-back writing the page anew.
pub(crate) fn disarm(at: usize, len: usize, again: bool) {
    if !on() || len == 0 {
        return;
    }
    for page in at / PAGE..(at + len).div_ceil(PAGE) {
        if !take(page) {
            continue;
        }
        if again {
            COUNT[AGAIN].fetch_add(1, Relaxed);
        } else {
            layer_touch(page);
        }
        set_guard(page * PAGE, false);
    }
}

/// After a copy-back wrote `[at, at + len)`: its pages are guarded.
pub(crate) fn arm(at: usize, len: usize) {
    if !on() || len == 0 {
        return;
    }
    for page in at / PAGE..(at + len).div_ceil(PAGE) {
        if page >= PAGES {
            break;
        }
        let bit = 1u64 << (page % 64);
        // The bits before the guard: a hit at once is then the census's.
        ever()[page / 64].fetch_or(bit, Relaxed);
        if bits()[page / 64].fetch_or(bit, Relaxed) & bit != 0 {
            continue;
        }
        if set_guard(page * PAGE, true) {
            COUNT[ARMED].fetch_add(1, Relaxed);
            let (kind, id) = READER.with(std::cell::Cell::get);
            owners().lock().unwrap_or_else(|e| e.into_inner()).insert(page, if kind == MERGE { id } else { 0 });
        } else {
            bits()[page / 64].fetch_and(!bit, Relaxed);
        }
    }
    report();
}

/// Puts on or takes off `PAGE_GUARD` at one committed page, keeping the
/// rest of its protection.
fn set_guard(at: usize, guard: bool) -> bool {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualProtect, VirtualQuery,
    };
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a query of any address; the out struct is ours.
    if unsafe { VirtualQuery(at as _, &mut m, std::mem::size_of_val(&m)) } == 0 || m.State != MEM_COMMIT {
        return false;
    }
    if m.Protect & PAGE_NOACCESS != 0 || (m.Protect & PAGE_GUARD != 0) == guard {
        return false;
    }
    let protect = if guard { m.Protect | PAGE_GUARD } else { m.Protect & !PAGE_GUARD };
    let mut old = 0;
    // SAFETY: one committed page of title memory; only its guard bit changes.
    unsafe { VirtualProtect(at as _, PAGE, protect, &mut old) != 0 }
}

/// A line every five seconds: pages a second.
fn report() {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let last = LAST.load(Relaxed);
    if now < last + 5 || LAST.compare_exchange(last, now, Relaxed, Relaxed).is_err() {
        return;
    }
    let secs = if last == 0 { 5.0 } else { (now - last) as f64 };
    let c: Vec<f64> = COUNT.iter().map(|c| c.swap(0, Relaxed) as f64 / secs).collect();
    let mb = |pages: f64| pages * PAGE as f64 / 1e6;
    let rips: Vec<String> = FIRST_RIPS.iter().map(|r| r.load(Relaxed)).filter(|&r| r != 0).map(|r| format!("{r:#x}")).collect();
    tracing::info!(
        "read census, per second: {:.1} MB of copied-back pages guarded; touched by the title: {:.2} MB read, {:.2} MB written; by the layer {:.1} MB (its own copy {:.1}, another copy {:.1}, textures {:.1}, untagged {:.1}); copied back again untouched {:.1} MB; races {} (first title readers: {})",
        mb(c[ARMED]),
        mb(c[TITLE_READ]),
        mb(c[TITLE_WRITE]),
        mb(c[HOST]),
        mb(c[SAME]),
        mb(c[OTHER]),
        mb(c[TEX]),
        mb(c[UNTAGGED]),
        mb(c[AGAIN]),
        RACES.load(Relaxed),
        rips.join(" ")
    );
}
