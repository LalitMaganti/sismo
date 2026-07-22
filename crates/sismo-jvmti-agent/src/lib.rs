// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Passive JVMTI perf-map agent (JIT-1's JVM producer).
//!
//! HotSpot only writes a perf-map itself on Linux (`jcmd Compiler.perfmap` is
//! `#if defined(LINUX)`), so on macOS/Windows the JIT method names have to
//! come from inside the JVM. This agent is the smallest possible in-process
//! producer: on load/attach it enables `CompiledMethodLoad` +
//! `DynamicCodeGenerated`, replays already-compiled methods via
//! `GenerateEvents` (the live-attach case), and appends one
//! `<hex-start> <hex-size> <name>` line per code blob to
//! `/tmp/perf-<pid>.map`. No sampling, no threads, no JNI use beyond the
//! JVMTI environment — sismo remains the only profiler in the process.
//!
//! The JVMTI ABI subset used here is declared by hand from the JVMTI spec
//! (function-table indices, the 16-byte capabilities bitset, event callback
//! slot positions), verified against JDK 26's jvmti.h — nothing is vendored,
//! and the layout is fixed by the spec's binary-compatibility rules.

use std::ffi::{c_char, c_void, CStr};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

// ---- JVMTI ABI subset (spec-defined, stable) --------------------------------

const JVMTI_VERSION_1_2: i32 = 0x3001_0200;
const JVMTI_ENABLE: u32 = 1;
const JVMTI_EVENT_COMPILED_METHOD_LOAD: u32 = 68;
const JVMTI_EVENT_DYNAMIC_CODE_GENERATED: u32 = 70;

// jvmtiCapabilities: 128-bit bitset; can_generate_compiled_method_load_events
// is the 28th one-bit field (word 0, bit 27).
const CAP_COMPILED_METHOD_LOAD: u32 = 1 << 27;

// Function-table indices from the spec (struct member N == array slot N-1;
// slot 0 is reserved1).
const IDX_SET_EVENT_NOTIFICATION_MODE: usize = 2;
const IDX_DEALLOCATE: usize = 47;
const IDX_GET_CLASS_SIGNATURE: usize = 48;
const IDX_GET_METHOD_NAME: usize = 64;
const IDX_GET_METHOD_DECLARING_CLASS: usize = 65;
const IDX_SET_EVENT_CALLBACKS: usize = 122;
const IDX_GENERATE_EVENTS: usize = 123;
const IDX_ADD_CAPABILITIES: usize = 142;

// jvmtiEventCallbacks slot positions (each slot one fn pointer).
const CB_COMPILED_METHOD_LOAD: usize = 18;
const CB_DYNAMIC_CODE_GENERATED: usize = 20;
const CB_SLOTS: usize = 21; // SetEventCallbacks copies only what we pass

type JvmtiEnv = *mut *const *const c_void; // env -> function table -> slots
type JavaVm = *mut *const *const c_void;
type JMethodId = *const c_void;
type JClass = *const c_void;

/// Fetch function-table slot `idx` (1-based spec index) from a jvmtiEnv.
unsafe fn vt(env: JvmtiEnv, idx: usize) -> *const c_void {
    *(*env).add(idx - 1)
}

macro_rules! jvmti_fn {
    ($env:expr, $idx:expr, $ty:ty) => {
        std::mem::transmute::<*const c_void, $ty>(vt($env, $idx))
    };
}

unsafe fn deallocate(env: JvmtiEnv, mem: *mut c_char) {
    if !mem.is_null() {
        let f = jvmti_fn!(env, IDX_DEALLOCATE, extern "C" fn(JvmtiEnv, *mut c_char) -> i32);
        f(env, mem);
    }
}

// ---- perf-map output ---------------------------------------------------------

static MAP_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

fn map_file() -> Option<&'static Mutex<std::fs::File>> {
    // Truncate on first open: a re-attach replays everything via
    // GenerateEvents, so starting clean beats duplicating a stale map.
    MAP_FILE
        .get_or_init(|| {
            let path = format!("/tmp/perf-{}.map", std::process::id());
            Mutex::new(std::fs::File::create(path).unwrap_or_else(|_| {
                // An unwritable /tmp leaves a dead sink; never panic in-target.
                std::fs::File::create("/dev/null").expect("/dev/null")
            }))
        })
        .into()
}

fn write_entry(start: u64, size: u64, name: &str) {
    if let Some(f) = map_file() {
        if let Ok(mut f) = f.lock() {
            let _ = writeln!(f, "{start:x} {size:x} {name}");
        }
    }
}

/// `Ljava/lang/String;` + `indexOf` -> `java.lang.String::indexOf`.
pub fn clean_name(class_sig: &str, method: &str) -> String {
    let cls = class_sig
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
        .unwrap_or(class_sig)
        .replace('/', ".");
    format!("{cls}::{method}")
}

// ---- event callbacks ---------------------------------------------------------

extern "C" fn compiled_method_load(
    env: JvmtiEnv,
    method: JMethodId,
    code_size: i32,
    code_addr: *const c_void,
    _map_length: i32,
    _map: *const c_void,
    _compile_info: *const c_void,
) {
    unsafe {
        let get_name = jvmti_fn!(
            env,
            IDX_GET_METHOD_NAME,
            extern "C" fn(JvmtiEnv, JMethodId, *mut *mut c_char, *mut *mut c_char, *mut *mut c_char) -> i32
        );
        let get_class = jvmti_fn!(
            env,
            IDX_GET_METHOD_DECLARING_CLASS,
            extern "C" fn(JvmtiEnv, JMethodId, *mut JClass) -> i32
        );
        let get_class_sig = jvmti_fn!(
            env,
            IDX_GET_CLASS_SIGNATURE,
            extern "C" fn(JvmtiEnv, JClass, *mut *mut c_char, *mut *mut c_char) -> i32
        );

        let mut mname: *mut c_char = std::ptr::null_mut();
        if get_name(env, method, &mut mname, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
            return;
        }
        let mut class: JClass = std::ptr::null();
        let mut csig: *mut c_char = std::ptr::null_mut();
        let have_cls =
            get_class(env, method, &mut class) == 0 && get_class_sig(env, class, &mut csig, std::ptr::null_mut()) == 0;

        let method_str = CStr::from_ptr(mname).to_string_lossy();
        let name = if have_cls && !csig.is_null() {
            clean_name(&CStr::from_ptr(csig).to_string_lossy(), &method_str)
        } else {
            method_str.into_owned()
        };
        write_entry(code_addr as u64, code_size as u64, &name);

        deallocate(env, mname);
        if have_cls {
            deallocate(env, csig);
        }
    }
}

extern "C" fn dynamic_code_generated(
    _env: JvmtiEnv,
    name: *const c_char,
    address: *const c_void,
    length: i32,
) {
    if name.is_null() {
        return;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    write_entry(address as u64, length as u64, &name);
}

// ---- agent entry points --------------------------------------------------------

/// Shared init: capabilities, callbacks, notifications, and — when attaching
/// to a live JVM — a replay of everything already compiled.
unsafe fn init(vm: JavaVm, live_attach: bool) -> i32 {
    // JNIInvokeInterface slot 6 = GetEnv.
    let get_env = std::mem::transmute::<*const c_void, extern "C" fn(JavaVm, *mut *mut c_void, i32) -> i32>(*(*vm).add(6));
    let mut env_ptr: *mut c_void = std::ptr::null_mut();
    if get_env(vm, &mut env_ptr, JVMTI_VERSION_1_2) != 0 || env_ptr.is_null() {
        return -1;
    }
    let env = env_ptr as JvmtiEnv;

    let caps: [u32; 4] = [CAP_COMPILED_METHOD_LOAD, 0, 0, 0];
    let add_caps = jvmti_fn!(env, IDX_ADD_CAPABILITIES, extern "C" fn(JvmtiEnv, *const u32) -> i32);
    if add_caps(env, caps.as_ptr()) != 0 {
        return -1;
    }

    let mut callbacks = [std::ptr::null::<c_void>(); CB_SLOTS];
    callbacks[CB_COMPILED_METHOD_LOAD] = compiled_method_load as *const c_void;
    callbacks[CB_DYNAMIC_CODE_GENERATED] = dynamic_code_generated as *const c_void;
    let set_cbs = jvmti_fn!(
        env,
        IDX_SET_EVENT_CALLBACKS,
        extern "C" fn(JvmtiEnv, *const *const c_void, i32) -> i32
    );
    if set_cbs(env, callbacks.as_ptr(), (CB_SLOTS * std::mem::size_of::<*const c_void>()) as i32) != 0 {
        return -1;
    }

    let set_mode = jvmti_fn!(
        env,
        IDX_SET_EVENT_NOTIFICATION_MODE,
        extern "C" fn(JvmtiEnv, u32, u32, *const c_void) -> i32
    );
    set_mode(env, JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, std::ptr::null());
    set_mode(env, JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, std::ptr::null());

    if live_attach {
        let gen = jvmti_fn!(env, IDX_GENERATE_EVENTS, extern "C" fn(JvmtiEnv, u32) -> i32);
        gen(env, JVMTI_EVENT_COMPILED_METHOD_LOAD);
        gen(env, JVMTI_EVENT_DYNAMIC_CODE_GENERATED);
    }
    0
}

/// -agentpath at JVM launch.
///
/// # Safety
/// Called only by the JVM, which passes a valid JavaVM pointer.
#[no_mangle]
pub unsafe extern "C" fn Agent_OnLoad(vm: JavaVm, _options: *mut c_char, _reserved: *mut c_void) -> i32 {
    init(vm, false)
}

/// Live attach (`jcmd <pid> JVMTI.agent_load <path>`): replay compiled code.
///
/// # Safety
/// Called only by the JVM, which passes a valid JavaVM pointer.
#[no_mangle]
pub unsafe extern "C" fn Agent_OnAttach(vm: JavaVm, _options: *mut c_char, _reserved: *mut c_void) -> i32 {
    init(vm, true)
}

#[cfg(test)]
mod tests {
    use super::clean_name;

    #[test]
    fn cleans_class_signatures() {
        assert_eq!(clean_name("Ljava/lang/String;", "indexOf"), "java.lang.String::indexOf");
        assert_eq!(clean_name("LWorkload;", "sismo_wl_leaf"), "Workload::sismo_wl_leaf");
        // Defensive: an unexpected signature shape passes through un-mangled.
        assert_eq!(clean_name("[B", "clone"), "[B::clone");
    }
}
