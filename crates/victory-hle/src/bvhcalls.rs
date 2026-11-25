//! `VICTORY_BVH_CALLS=1` (diagnostics): the title's calls into the console's ray-tracing
//! structure builder (`XboxBvhBuilder.dll`), logged with their arguments and results.
//!
//! The library is title code; the title reaches it through its import table. The slots of
//! the calls below are pointed at wrappers that log and then call the library: the sizes
//! the library promises (`GetRaytracingAccelerationStructurePrebuildInfo`, which the title
//! allocates by), the builds and rehydrations it is asked for, and the copies. Set against
//! what the builder's programs write (fork #16), they say whether a build writes past the
//! memory its promise sized.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};

static ORIGINAL: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static CALLS: AtomicU64 = AtomicU64::new(0);

/// The first calls are logged whole; later ones every 50th, the log stays readable.
fn logged() -> bool {
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    n < 4000 || n % 50 == 0
}

/// `D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS`.
#[repr(C)]
struct Inputs {
    kind: u32,
    flags: u32,
    descs: u32,
    layout: u32,
    data: u64,
}

/// `D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC`.
#[repr(C)]
struct BuildDesc {
    dest: u64,
    inputs: Inputs,
    source: u64,
    scratch: u64,
}

fn hex(at: *const u8, len: usize) -> String {
    if at.is_null() {
        return "null".into();
    }
    // SAFETY: the title's argument; diagnostics only, short reads of its own memory.
    let bytes = unsafe { std::slice::from_raw_parts(at, len) };
    bytes.chunks(8).map(|c| format!("{:016x}", u64::from_le_bytes(c.try_into().unwrap_or([0; 8])))).collect::<Vec<_>>().join(" ")
}

type Prebuild = extern "system" fn(*mut c_void, *const Inputs, *const c_void, *mut [u64; 3]);
extern "system" fn prebuild(this: *mut c_void, inputs: *const Inputs, stream: *const c_void, out: *mut [u64; 3]) {
    // SAFETY: the library's own routine of this type.
    let f: Prebuild = unsafe { std::mem::transmute(ORIGINAL[0].load(Ordering::Relaxed)) };
    f(this, inputs, stream, out);
    if logged() {
        // SAFETY: the title's arguments, as the library just used them.
        let (i, o) = unsafe { (inputs.as_ref(), out.as_ref()) };
        if let (Some(i), Some(o)) = (i, o) {
            tracing::info!(
                kind = i.kind,
                flags = format_args!("{:#x}", i.flags),
                descs = i.descs,
                layout = i.layout,
                data = format_args!("{:#x}", i.data),
                stream = format_args!("{:#x}", stream as usize),
                result_max = format_args!("{:#x}", o[0]),
                scratch = format_args!("{:#x}", o[1]),
                update_scratch = format_args!("{:#x}", o[2]),
                "bvh call: prebuild info"
            );
        }
    }
}

type Build = extern "system" fn(*mut c_void, *mut c_void, u32, *const u8);
extern "system" fn build(this: *mut c_void, list: *mut c_void, count: u32, descs: *const u8) {
    if logged() {
        // The batched desc's layout is the console's own: its first 0x60 bytes, raw.
        tracing::info!(count, descs = format_args!("{:#x}", descs as usize), first = hex(descs, 0x60), "bvh call: build batched");
    }
    // SAFETY: the library's own routine of this type.
    let f: Build = unsafe { std::mem::transmute(ORIGINAL[1].load(Ordering::Relaxed)) };
    f(this, list, count, descs);
}

type Rehydrate = extern "system" fn(*mut c_void, *mut c_void, u32, *const BuildDesc, *const u64) -> i32;
extern "system" fn rehydrate(this: *mut c_void, list: *mut c_void, count: u32, descs: *const BuildDesc, sizes: *const u64) -> i32 {
    // The serialized header of each structure, as the library is about to read it (through
    // the CPU address the fifth argument holds): what it sizes the rehydration by.
    let log = logged();
    let headers: Vec<String> = if log && !sizes.is_null() {
        // SAFETY: the title passes `count` CPU addresses of the structures.
        (0..count as usize).map(|k| hex(unsafe { *sizes.add(k) } as *const u8, 0x100)).collect()
    } else {
        Vec::new()
    };
    // SAFETY: the library's own routine of this type.
    let f: Rehydrate = unsafe { std::mem::transmute(ORIGINAL[2].load(Ordering::Relaxed)) };
    let result = f(this, list, count, descs, sizes);
    if log {
        for k in 0..count as usize {
            // SAFETY: the title passes `count` descriptions (and sizes, if not null).
            let (d, size) = unsafe { (&*descs.add(k), if sizes.is_null() { 0 } else { *sizes.add(k) }) };
            tracing::info!(
                header = headers.get(k).map_or("", String::as_str),
                count,
                index = k,
                result = format_args!("{result:#x}"),
                dest = format_args!("{:#x}", d.dest),
                kind = d.inputs.kind,
                descs = d.inputs.descs,
                data = format_args!("{:#x}", d.inputs.data),
                source = format_args!("{:#x}", d.source),
                scratch = format_args!("{:#x}", d.scratch),
                size = format_args!("{size:#x}"),
                "bvh call: rehydrate"
            );
        }
    }
    result
}

type Copy = extern "system" fn(*mut c_void, *mut c_void, u64, u64, u32);
extern "system" fn copy(this: *mut c_void, list: *mut c_void, dest: u64, source: u64, mode: u32) {
    if logged() {
        tracing::info!(dest = format_args!("{dest:#x}"), source = format_args!("{source:#x}"), mode, "bvh call: copy");
    }
    // SAFETY: the library's own routine of this type.
    let f: Copy = unsafe { std::mem::transmute(ORIGINAL[3].load(Ordering::Relaxed)) };
    f(this, list, dest, source, mode);
}

/// Points the title's import slots of the builder's calls (`(rva, which)`: 0 prebuild,
/// 1 build batched, 2 rehydrate batched, 3 copy) at the wrappers, with `VICTORY_BVH_CALLS=1`.
pub fn install(base: usize, slots: &[(usize, usize)]) {
    if !std::env::var_os("VICTORY_BVH_CALLS").is_some_and(|v| v == "1") {
        return;
    }
    let wrappers: [usize; 4] = [prebuild as *const () as usize, build as *const () as usize, rehydrate as *const () as usize, copy as *const () as usize];
    for &(rva, which) in slots {
        let slot = (base + rva) as *mut usize;
        let mut old = 0u32;
        // SAFETY: an import slot of the title's image, made writable for the store.
        unsafe {
            if VirtualProtect(slot.cast(), 8, PAGE_READWRITE, &mut old) == 0 {
                tracing::warn!(rva = format_args!("{rva:#x}"), "bvh calls: import slot not writable");
                continue;
            }
            ORIGINAL[which].store(slot.read(), Ordering::Relaxed);
            slot.write(wrappers[which]);
            VirtualProtect(slot.cast(), 8, old, &mut old);
        }
        tracing::info!(rva = format_args!("{rva:#x}"), which, "bvh calls: import slot wrapped (VICTORY_BVH_CALLS=1)");
    }
}
