use std::ffi::CStr;
use std::fs::File;
use std::os::raw::{c_char, c_void};

use crate::connection::{ConnState, Server};
use crate::filter::{install, install_uds_filters};
use crate::message::{
    Request, Tattach, Tauth, Tclunk, Tlcreate, Tlopen, Tremove, Tsetattrclunk, Tucreate, Twalk,
    Twalkgetattr,
};
use crate::rustfer::{
    is_read_only_mount, resolve_mounts, write_mounts, AttachPoint, AttachPointConfig, Config,
    Rustfer,
};
use crate::spec_utils::{is_external_mount, read_spec_from_file};
use crate::wasm_mem::alloc;

#[no_mangle]
fn rustfer_allocate(size: i32) -> *mut c_void {
    alloc(size as usize)
}

#[no_mangle]
fn rustfer_deallocate(ptr: *mut c_void, size: i32) {
    let size = size as usize;
    unsafe {
        let data = Vec::from_raw_parts(ptr, size, size);
        std::mem::drop(data);
    }
}

#[no_mangle]
fn healthcheck() -> i8 {
    12
}

// rustfer_init corresponds to Gofer.Execute in Gofer.
#[no_mangle]
fn rustfer_init(
    //bundle_dir_ptr: *mut c_char,
    io_fds_len: i32,
    io_fds_ptr: *mut i8,
    apply_caps: bool,
    set_up_root: bool,
    config: *mut c_char,
) {
    // let bundle_dir = unsafe { CStr::from_ptr(bundle_dir_ptr) }
    //     .to_str()
    //     .unwrap()
    //     .to_string();
    let mut io_fds = Vec::new();
    for i in 0..io_fds_len {
        unsafe { io_fds.push(*io_fds_ptr.offset(i as isize)) }
    }
    if Rustfer::init(
        // bundle_dir.clone(),
        io_fds.clone(),
        apply_caps,
        set_up_root,
    )
    .is_err()
    {
        panic!("failed to initialize Rustfer.");
    }
    let config = unsafe { CStr::from_ptr(config) }.to_str().unwrap();
    let mut config: Config = serde_json::from_str(&config).unwrap();
    let spec_file = File::open("/config/config.json").expect("no such file named \"spec file\"");
    let mut spec = read_spec_from_file(/*&bundle_dir, */ spec_file, &mut config)
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
                    "Serving {} mapped on FD {} (ro: {})",
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

    configure_server(ats, io_fds);
}

fn configure_server(ats: Vec<AttachPoint>, io_fds: Vec<i8>) {
    for i in 0..ats.len() {
        let io_fd = io_fds[i] as i32;
        let at = &ats[i];
        let server = Server::new(Box::new(at.clone()));
        let conn_state = ConnState::new(server);
        ConnState::insert_conn_state(io_fd, conn_state);
    }
}

#[no_mangle]
fn rustfer_tlopen(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tlopen::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tclunk(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tclunk::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tsetattrclunk(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tsetattrclunk::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tremove(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tremove::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tattach(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tattach::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tucreate(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tucreate::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tlcreate(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tlcreate::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_tauth(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Tauth::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_twalk(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Twalk::from_ptr(msg).handle(io_fd)
}

#[no_mangle]
fn rustfer_twalkgetattr(io_fd: i32, msg: *mut c_char) -> *const u8 {
    Twalkgetattr::from_ptr(msg).handle(io_fd)
}
