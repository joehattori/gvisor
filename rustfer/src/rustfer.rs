use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File as OsFile};
use std::hash::{Hash, Hasher};
use std::io::{self, prelude::*};
use std::os::wasi::prelude::*;
use std::path::{self, Path};
use std::sync::{Arc, Mutex};

use oci_spec::runtime::Mount;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::fs::{Attacher, LocalFile};
use crate::message::{QIDType, QID};
use crate::spec_utils::is_supported_dev_mount;
use crate::unix;

pub const OPEN_FLAGS: i32 = unix::O_NOFOLLOW | unix::O_CLOEXEC;
pub const ALLOWED_OPEN_FLAGS: i32 = unix::O_TRUNC;

pub struct Rustfer {
    // bundle_dir: String,
    io_fds: Vec<i8>,
    apply_caps: bool,
    set_up_root: bool,
}

static APP: OnceCell<Mutex<Rustfer>> = OnceCell::new();

impl Rustfer {
    pub fn init(
        // bundle_dir: String,
        io_fds: Vec<i8>,
        apply_caps: bool,
        set_up_root: bool,
    ) -> Result<(), Mutex<Self>> {
        let r = Rustfer {
            // bundle_dir,
            io_fds,
            apply_caps,
            set_up_root,
        };
        APP.set(Mutex::new(r))
    }

    pub fn get() -> &'static Mutex<Self> {
        &*APP.get().unwrap()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    root_dir: String,
    traceback: String,
    debug: bool,
    log_file_name: String,
    log_format: String,
    debug_log: String,
    panic_log: String,
    debug_log_format: String,
    file_access: i32,
    pub overlay: bool,
    pub verity: bool,
    pub fs_rustfer_host_uds: bool,
    network: i32,
    enable_raw: bool,
    hardware_gso: bool,
    software_gso: bool,
    tx_checksum_offload: bool,
    rx_checksum_offload: bool,
    qdisc: i32,
    log_packets: bool,
    platform: String,
    strace: bool,
    strace_syscalls: String,
    strace_log_size: u32,
    disable_seccomp: bool,
    watchdog_action: i32,
    panic_signal: i32,
    profile_enable: bool,
    restore_file: String,
    num_network_channels: i32,
    rootless: bool,
    also_log_to_stderr: bool,
    reference_leak: u32,
    overlayfs_stale_read: bool,
    cpu_num_from_quota: bool,
    vfs2: bool,
    fuse: bool,
    allow_flag_override: bool,
    oci_seccomp: bool,
    pub test_only_allow_run_as_current_user_without_chroot: bool,
    test_only_test_name_env: String,
}

impl Config {
    pub fn override_flag(&mut self, name: &str, value: &str) -> Result<(), &str> {
        if !self.allow_flag_override {
            return Err("flag override disabled, use --allow-flag-override to enable it.");
        }
        match name {
            "root" => self.root_dir = value.parse().unwrap(),
            "traceback" => self.traceback = value.parse().unwrap(),
            "debug" => self.debug = value.parse().unwrap(),
            "log" => self.log_file_name = value.parse().unwrap(),
            "log-format" => self.log_format = value.parse().unwrap(),
            "debug-log" => self.debug_log = value.parse().unwrap(),
            "panic-log" => self.panic_log = value.parse().unwrap(),
            "debug-log-format" => self.debug_log_format = value.parse().unwrap(),
            "file-access" => self.file_access = value.parse().unwrap(),
            "overlay" => self.overlay = value.parse().unwrap(),
            "verity" => self.verity = value.parse().unwrap(),
            "fsgofer-host-uds" => self.fs_rustfer_host_uds = value.parse().unwrap(),
            "network" => self.network = value.parse().unwrap(),
            "net-raw" => self.enable_raw = value.parse().unwrap(),
            "gso" => self.hardware_gso = value.parse().unwrap(),
            "software-gso" => self.software_gso = value.parse().unwrap(),
            "tx-checksum-offload" => self.tx_checksum_offload = value.parse().unwrap(),
            "rx-checksum-offload" => self.rx_checksum_offload = value.parse().unwrap(),
            "qdisc" => self.qdisc = value.parse().unwrap(),
            "log-packets" => self.log_packets = value.parse().unwrap(),
            "platform" => self.platform = value.parse().unwrap(),
            "strace" => self.strace = value.parse().unwrap(),
            "strace-syscalls" => self.strace_syscalls = value.parse().unwrap(),
            "strace-log-size" => self.strace_log_size = value.parse().unwrap(),
            "watchdog-action" => self.watchdog_action = value.parse().unwrap(),
            "panic-signal" => self.panic_signal = value.parse().unwrap(),
            "profile" => self.profile_enable = value.parse().unwrap(),
            "num-network-channels" => self.num_network_channels = value.parse().unwrap(),
            "rootless" => self.rootless = value.parse().unwrap(),
            "alsologtostderr" => self.also_log_to_stderr = value.parse().unwrap(),
            "ref-leak-mode" => self.reference_leak = value.parse().unwrap(),
            "overlayfs-stale-read" => self.overlayfs_stale_read = value.parse().unwrap(),
            "cpu-num-from-quota" => self.cpu_num_from_quota = value.parse().unwrap(),
            "vfs2" => self.vfs2 = value.parse().unwrap(),
            "fuse" => self.fuse = value.parse().unwrap(),
            "allow-flag-override" => self.allow_flag_override = value.parse().unwrap(),
            "oci-seccomp" => self.oci_seccomp = value.parse().unwrap(),
            "TESTONLY-unsafe-nonroot" => {
                self.test_only_allow_run_as_current_user_without_chroot = value.parse().unwrap()
            }
            "TESTONLY-test-name-env" => self.test_only_test_name_env = value.parse().unwrap(),
            _ => {
                eprintln!("flag {} not found. Cannot set it to {}.", name, value);
                return Err("flag not found.");
            }
        };
        Ok(())
    }
}

// pub fn setup_root_fs(spec: Spec, conf: Config) -> Result<(), &str> {}

pub fn write_mounts(mounts: &Vec<Mount>) -> io::Result<()> {
    // JOETODO: what do you mean by writing to a ro mount.
    // let bytes = serde_json::to_string(mounts).expect("couldn't serialize mounts to json.");
    // let mut file = OsFile::create("mountsfile")?;
    // file.write_all(bytes.as_bytes())?;
    Ok(())
}

pub fn resolve_mounts<'a>(
    conf: &'a Config,
    mounts: Option<Vec<Mount>>,
    root: &'a str,
) -> Result<Option<Vec<Mount>>, &'a str> {
    match mounts {
        None => Ok(None),
        Some(mounts) => {
            let mut clean_mounts = Vec::new();
            for m in mounts {
                if m.typ.clone().unwrap_or(String::new()) == "bind" || is_supported_dev_mount(&m) {
                    clean_mounts.push(m);
                    continue;
                }
                let dst = match resolve_symlinks(
                    root.to_string(),
                    root.to_string(),
                    m.destination.clone(),
                    255,
                ) {
                    Ok(d) => d,
                    Err(_) => return Err("resolving symlinks"),
                };
                let rel_dst = Path::new(&dst).strip_prefix(&root).unwrap_or_else(|e| {
                    eprintln!("{} could not be made relative to {}: {}", dst, root, e);
                    panic!("{} could not be made relative to {}: {}", dst, root, e)
                });
                let path = Path::new(&root);
                let path = path.join(rel_dst);
                let opts = adjust_mount_options(
                    &conf,
                    path.to_str().unwrap().to_string(),
                    m.options.clone(),
                )?;
                clean_mounts.push(Mount {
                    destination: Path::new("/").join(rel_dst).to_str().unwrap().to_string(),
                    typ: m.typ.clone(),
                    source: m.source.clone(),
                    options: opts,
                });
            }
            Ok(Some(clean_mounts))
        }
    }
}

fn resolve_symlinks<'a>(
    root: String,
    mut base: String,
    rel: String,
    follow_count: i32,
) -> Result<String, &'a str> {
    if follow_count == 0 {
        return Err("too many symlinks to follow");
    }
    // JOETODO: canonicalize() is not supported on this platform.
    // let rel = Path::new(&rel).canonicalize().unwrap();
    for name in Path::new(&rel).iter() {
        if name == OsStr::new(&path::MAIN_SEPARATOR.to_string()) {
            continue;
        }
        let path = Path::new(&base);
        let path = path.join(name.clone());
        let path = path.as_path();
        if path.starts_with(&root) {
            base = root.clone();
            continue;
        }
        let is_symlink = fs::metadata(path).unwrap().file_type().is_symlink();
        if is_symlink {
            let link = match fs::read_link(path) {
                Ok(link) => link,
                Err(e) => return Err("e"),
            };
            if link.is_absolute() {
                base = root.clone();
            }
            base = resolve_symlinks(
                root.clone(),
                base,
                link.to_str().unwrap().to_string(),
                follow_count - 1,
            )?;
            continue;
        }
        base = path.to_str().unwrap().to_string();
    }
    Ok(base)
}

fn adjust_mount_options(
    conf: &Config,
    path: String,
    opts: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, &str> {
    let mut ret = opts.clone();
    if conf.overlayfs_stale_read {
        // TODO
    }
    Ok(ret)
}

// static PROC_SELF_FD: OnceCell<Mutex<Fd>> = OnceCell::new();
//
// pub fn open_proc_self_fd() -> io::Result<()> {
//     let path = CString::new("/proc/self/fd").unwrap();
//     let fd = unsafe {
//         libc::open(
//             path.as_ptr(),
//             (unix::O_RDONLY | unix::O_DIRECTORY) as i32,
//             0,
//         )
//     };
//     if fd < 0 {
//         Err(Error::new(ErrorKind::Other, "error opening /proc/self/fd"))
//     } else {
//         match PROC_SELF_FD.set(Mutex::new(Fd(fd))) {
//             Ok(_) => Ok(()),
//             Err(_) => Err(Error::new(
//                 ErrorKind::Other,
//                 "failed to set to PROC_SELF_FD.",
//             )),
//         }
//     }
// }

pub fn is_read_only_mount(opts: Option<Vec<String>>) -> bool {
    match opts {
        Some(opts) => opts.iter().any(|o| o == "ro"),
        None => false,
    }
}

#[derive(Clone, Default)]
pub struct AttachPoint {
    prefix: String,
    pub config: AttachPointConfig,
    attached: Arc<Mutex<bool>>,
    next_device: Arc<Mutex<u8>>,
    devices: Arc<Mutex<HashMap<u64, u8>>>,
}

impl AttachPoint {
    pub fn new<'a>(prefix: &'a str, config: AttachPointConfig) -> Result<Self, &'a str> {
        if !Path::new(prefix).is_absolute() {
            eprintln!("attach point prefix must be absolute {}", prefix);
            Err("attach point prefix must be absolute")
        } else {
            Ok(AttachPoint {
                prefix: prefix.to_string(),
                config,
                attached: Arc::new(Mutex::new(false)),
                next_device: Arc::new(Mutex::new(0)),
                devices: Arc::new(Mutex::new(HashMap::new())),
            })
        }
    }

    pub fn make_qid(&self, metadata: &fs::Metadata) -> QID {
        let mut devices = self.devices.lock().unwrap();
        let mut next_device = self.next_device.lock().unwrap();
        let dev = match devices.get(&metadata.dev()) {
            Some(d) => *d,
            None => {
                devices.insert(metadata.dev(), *next_device);
                let dev = *next_device;
                *next_device += 1;
                if *next_device < dev {
                    panic!("device id overflow! map: {:?}", devices);
                }
                dev
            }
        };
        let ino = metadata.ino();
        let masked_ino = ino & 0x00ffffffffffffff;
        if masked_ino != ino {
            eprintln!(
                "first 8 bytes of host inode id {} will be truncated to construct virtual inode id",
                ino
            );
        }
        let ino = (dev as u64) << 56 | masked_ino;
        QID {
            typ: QIDType::from_file_type(metadata.file_type()),
            path: ino,
            version: 0,
        }
    }
}

impl Attacher for AttachPoint {
    fn attach(&self) -> io::Result<LocalFile> {
        let mut attached = self.attached.lock().unwrap();
        if *attached {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("attach point already attached, prefix: {}", self.prefix),
            ));
        }
        let prefix = self.prefix.to_owned();
        let (file, readable) = open_any_file(Box::new(move |option: &fs::OpenOptions| {
            option.open(&prefix)
        }))?;
        match LocalFile::new(self, file, &self.prefix, readable) {
            Ok(lf) => {
                *attached = true;
                Ok(lf)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unable to create LocalFile {}: {}", self.prefix, e),
            )),
        }
    }
}

impl PartialEq for AttachPoint {
    fn eq(&self, other: &Self) -> bool {
        // JOETODO: perform more properly.
        self.prefix == other.prefix && self.config == other.config
    }
}

impl Eq for AttachPoint {}

impl Hash for AttachPoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // JOETODO: change here after changing PartialEq
        self.prefix.hash(state);
        self.config.hash(state);
    }
}

#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct AttachPointConfig {
    pub ro_mount: bool,
    pub panic_on_write: bool,
    pub host_uds: bool,
    pub enable_x_attr: bool,
}

fn join(parent: &str, child: &str) -> String {
    if child == "." || child == ".." {
        panic!("invalid child path {}", child)
    }
    Path::new(parent)
        .join(child)
        .as_path()
        .to_str()
        .unwrap()
        .to_string()
}

pub fn open_any_file_from_parent(
    parent: &LocalFile,
    name: &str,
) -> io::Result<(OsFile, String, bool)> {
    println!("open_any_file_from_parent: {} {}", &parent.host_path, name);
    let file_path = join(&parent.host_path, name);
    println!("file_path: {}", file_path);
    let cloned = file_path.to_owned();
    let (file, readable) = open_any_file(Box::new(move |option: &fs::OpenOptions| {
        option.open(&cloned)
    }))?;
    Ok((file, file_path, readable))
}

pub fn open_any_file<'a>(
    f: Box<dyn Fn(&fs::OpenOptions) -> io::Result<OsFile>>,
) -> io::Result<(OsFile, bool)> {
    #[derive(Debug)]
    struct Mode<'a> {
        open_option: &'a fs::OpenOptions,
        readable: bool,
    }
    let mut op = fs::OpenOptions::new();

    let modes = [
        Mode {
            open_option: op.read(true),
            readable: true,
        },
        Mode {
            open_option: &fs::OpenOptions::new(),
            readable: false,
        },
    ];
    let mut error = io::Error::new(io::ErrorKind::Other, "");
    for mode in modes.iter() {
        match f(mode.open_option) {
            Ok(file) => {
                eprintln!("Attempt to open file succeed!");
                return Ok((file, mode.readable));
            }
            Err(err) => {
                if err.raw_os_error() == Some(unix::ENOENT) {
                    return Err(err);
                }
                error = err;
                eprintln!(
                    "Attempt to open file failed, mode: {:?}, err: {}",
                    mode, error
                );
            }
        };
    }
    eprintln!("Attempt to open file failed, err: {}", error);
    Err(error)
}
