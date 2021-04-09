use std::ffi::CStr;
use std::fs::File;
use std::os::raw::{c_char, c_int, c_void};

use crate::connection::ConnState;
use crate::filter::{install, install_uds_filters};
use crate::message::{
    handle, Request, Tattach, Tauth, Tclunk, Tlopen, Tremove, Tsetattrclunk, Tucreate,
};
use crate::rustfer::{
    is_read_only_mount, resolve_mounts, write_mounts, AttachPoint, AttachPointConfig, Config,
    Rustfer,
};
use crate::spec_utils::{is_external_mount, read_spec_from_file};

#[no_mangle]
fn rustfer_allocate(size: usize) -> *mut c_void {
    let mut buffer = Vec::with_capacity(size);
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);

    pointer as *mut c_void
}

#[no_mangle]
fn rustfer_deallocate(pointer: *mut c_void, capacity: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(pointer, 0, capacity);
    }
}

// rustfer_init corresponds to Gofer.Execute in Gofer.
#[no_mangle]
fn rustfer_init(
    bundle_dir_ptr: *mut c_char,
    io_fds_ptr: *mut c_int,
    io_fds_len: i32,
    apply_caps: bool,
    set_up_root: bool,
    spec_fd: i32,
    mounts_fd: i32,
    config: *mut c_char,
) {
    let bundle_dir = unsafe { CStr::from_ptr(bundle_dir_ptr) }
        .to_str()
        .unwrap()
        .to_string();
    let mut io_fds = Vec::new();
    for i in 0..io_fds_len {
        unsafe { io_fds.push(*io_fds_ptr.offset(i as isize)) }
    }
    if Rustfer::init(
        bundle_dir.clone(),
        io_fds.clone(),
        apply_caps,
        set_up_root,
        spec_fd,
        mounts_fd,
    )
    .is_err()
    {
        panic!("failed to initialize Rustfer.");
    }
    let config = unsafe { CStr::from_ptr(config) }.to_str().unwrap();
    let mut config: Config = serde_json::from_str(&config).unwrap();
    let spec_file = File::open("spec file").expect("no such file named \"spec file\"");
    let mut spec = read_spec_from_file(&bundle_dir, spec_file, &mut config)
        .unwrap_or_else(|e| panic!("reading spec {}", e));
    if set_up_root {
        // TODO: setup_root_fs(spec, config).unwrap_or_else(|e| panic!("Error setting up root FS: {}", e));
        panic!("not implemented");
    }
    if apply_caps {
        // TODO
        panic!("unreachable");
    }

    let (root, root_read_only) = match spec.root {
        Some(root) => (root.path, root.readonly.unwrap_or(false)),
        None => {
            if config.test_only_allow_run_as_current_user_without_chroot {
                panic!("spec.root is empty.")
            } else {
                ("/root".to_string(), false)
            }
        }
    };

    let clean_mounts = resolve_mounts(&config, spec.mounts, &root)
        .unwrap_or_else(|e| panic!("failure to resolve mounts: {}", e));
    if let Some(ref clean_mounts) = &clean_mounts {
        write_mounts(clean_mounts).unwrap_or_else(|e| panic!("failed to write mounts: {}", e));
    }
    spec.mounts = clean_mounts;

    // TODO: LogSpec

    // in gVisor, unix.Umask(0) is performed but this should be unneeded in wasi.

    // open_proc_self_fd().unwrap_or_else(|e| panic!("failed to open /proc/self/fd: {}", e));

    // in gVisor, unix.Chroot(root) and unix.Chdir("/") is performed but this should be unneeded in wasi.
    let mut ats = Vec::new();
    let ap = AttachPoint::new(
        "/",
        AttachPointConfig {
            ro_mount: root_read_only || config.overlay,
            panic_on_write: false,
            host_uds: false,
            enable_x_attr: config.verity,
        },
    )
    .unwrap_or_else(|e| panic!("creating attach point: {}", e));
    ats.push(ap);
    println!(
        "Serving {} mapped to {} on FD {} (ro: {})",
        "/", &root, io_fds[0], root_read_only
    );

    let mut mount_idx = 1;
    if let Some(mounts) = spec.mounts {
        for m in mounts {
            if is_external_mount(&m) {
                let cfg = AttachPointConfig {
                    ro_mount: is_read_only_mount(m.options.clone()) || config.overlay,
                    panic_on_write: false,
                    host_uds: config.fs_rustfer_host_uds,
                    enable_x_attr: config.verity,
                };
                let ro_mount = cfg.ro_mount;
                let dst = m.destination.clone();
                let ap = AttachPoint::new(&dst, cfg)
                    .unwrap_or_else(|e| panic!("creating attach point: {}", e));
                ats.push(ap);
                if mount_idx >= io_fds_len {
                    panic!(
                        "no FD found for mount. Did you forget --io-fd? mount: {}, {:?}",
                        io_fds_len, m
                    );
                }
                println!(
                    "serving {} mapped on FD {} (ro: {})",
                    dst, io_fds[mount_idx as usize], ro_mount
                );
                mount_idx += 1;
            }
        }
    }
    if mount_idx != io_fds_len {
        panic!(
            "too many FDs passed from mounts. mounts: {}, FDs: {}",
            mount_idx, io_fds_len
        );
    }
    if config.fs_rustfer_host_uds {
        install_uds_filters();
    }
    install().unwrap_or_else(|e| panic!("installing seccomp filters: {}", e));
}

fn configure_server(ats: Vec<AttachPoint>, io_fds: Vec<i32>) {
    // for at in ats {
    //     let server = Server::new(Box::new(at));
    //     let cs = ConnState::new(s, conn);
    // }
}

#[no_mangle]
fn rustfer_topen(msg: *mut c_char) -> *const u8 {
    let tlopen = Tlopen::from_ptr(msg);
    handle(*tlopen)
}

#[no_mangle]
fn rustfer_tclunk(msg: *mut c_char) -> *const u8 {
    let tclunk = Tclunk::from_ptr(msg);
    handle(*tclunk)
}

#[no_mangle]
fn rustfer_tsetattrclunk(msg: *mut c_char) -> *const u8 {
    let tsetattrclunk = Tsetattrclunk::from_ptr(msg);
    handle(*tsetattrclunk)
}

#[no_mangle]
fn rustfer_tremove(msg: *mut c_char) -> *const u8 {
    let tremove = Tremove::from_ptr(msg);
    handle(*tremove)
}

#[no_mangle]
fn rustfer_tattach(msg: *mut c_char) -> *const u8 {
    let tattach = Tattach::from_ptr(msg);
    handle(*tattach)
}

#[no_mangle]
fn rustfer_tucreate(msg: *mut c_char) -> *const u8 {
    let tucreate = Tucreate::from_ptr(msg);
    handle(*tucreate)
}

#[no_mangle]
fn rustfer_tauth(msg: *mut c_char) -> *const u8 {
    let tauth = Tauth::from_ptr(msg);
    handle(*tauth)
}
