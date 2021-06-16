use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::Path;

use crate::rustfer::Config;
use crate::unix;

use oci_spec::runtime::{Mount, Spec};
use once_cell::sync::Lazy;

fn format_spec_str(spec: String) -> String {
    spec.replace("\"action\"", "\"actions\"")
}

pub fn read_spec_from_file(
    //bundle_dir: &str,
    mut spec_file: File,
    conf: &mut Config,
) -> io::Result<Spec> {
    spec_file.seek(SeekFrom::Start(0))?;
    let mut spec_buf = String::new();
    spec_file.read_to_string(&mut spec_buf)?;
    spec_buf = format_spec_str(spec_buf);
    let mut spec: Spec = serde_json::from_str(&spec_buf)?;
    if let Err(err) = validate_spec(&spec) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid spec."));
    }
    // JOETODO
    // let root = match spec.root {
    //     None => {
    //         return Err(io::Error::new(
    //             io::ErrorKind::NotFound,
    //             "Spec.root shouldn't be empty.",
    //         ))
    //     }
    //     Some(root) => root,
    // };
    // spec.root = Some(Root {
    //     path: abs_path(bundle_dir, &root.path).to_string(),
    //     ..root
    // });
    // if let Some(ref mut mounts) = &mut spec.mounts {
    //     for mut m in mounts {
    //         let default = Some(abs_path(bundle_dir, &root.path).to_string());
    //         m.source = m.source.clone().map_or(default.clone(), |s| {
    //             if s.is_empty() {
    //                 default.clone()
    //             } else {
    //                 Some(s)
    //             }
    //         });
    //     }
    // }
    const FLAG_PREFIX: &str = "dev.gvisor.flag.";
    if let Some(annotations) = &spec.annotations {
        for (annotation, val) in annotations.iter() {
            if annotation.starts_with(FLAG_PREFIX) {
                let name = &annotation[FLAG_PREFIX.len()..];
                println!("Overriding flag: {}={}", name, val);
                if let Err(e) = conf.override_flag(name, val) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
    }
    Ok(spec)
}

// fn abs_path<'a>(base: &'a str, rel: &'a str) -> String {
//     if Path::new(rel).is_absolute() {
//         Path::new(rel).to_str().unwrap().to_string()
//     } else {
//         Path::new(base).join(rel).to_str().unwrap().to_string()
//     }
// }

fn validate_spec(spec: &Spec) -> Result<(), &str> {
    match &spec.process {
        Some(process) => {
            if process.args.is_none() {
                return Err("Spec.process.args must be defined.");
            }
            if process.selinux_label.is_some() {
                return Err("SELinux is not supported.");
            }
            if let Some(apparmor_profile) = &process.apparmor_profile {
                println!("AppArmor profile {} is being ignored.", apparmor_profile);
            }
            match process.no_new_privileges {
                Some(v) => {
                    if !v {
                        println!("noNewPrivileges ignored. PR_SET_NO_NEW_PRIVS is assumed to always be set.")
                    }
                }
                None => println!(
                    "noNewPrivileges ignored. PR_SET_NO_NEW_PRIVS is assumed to always be set."
                ),
            };
        }
        None => return Err("Spec.process must be defined."),
    };
    match &spec.root {
        Some(root) => {
            if root.path.len() == 0 {
                return Err("Spec.root.path must be defined.");
            }
        }
        None => return Err("Spec.root must be defined."),
    };
    if spec.solaris.is_some() {
        return Err("Spec.solaris is not supported.");
    }
    if spec.windows.is_some() {
        return Err("Spec.windows is not supported.");
    }
    if let Some(linux) = &spec.linux {
        if let Some(propagation) = &linux.rootfs_propagation {
            validate_rootfs_propagation(&propagation)?;
        }
    }
    if let Some(mounts) = &spec.mounts {
        for m in mounts {
            validate_mount(&m)?;
        }
    }
    match spec_container_type(&spec) {
        ContainerType::Container => {
            if sandbox_id(spec).is_none() {
                Err("spec has container-type of container, but no sandbox ID set.")
            } else {
                Ok(())
            }
        }
        ContainerType::Unknown => Err("unknown container-type"),
        _ => Ok(()),
    }
}

#[derive(Clone)]
struct Mapping {
    set: bool,
    val: i32,
}

static OPTIONS_MAP: Lazy<HashMap<&str, Mapping>> = Lazy::new(|| {
    [
        (
            "acl",
            Mapping {
                set: true,
                val: unix::MS_POSIXACL,
            },
        ),
        (
            "async",
            Mapping {
                set: false,
                val: unix::MS_SYNCHRONOUS,
            },
        ),
        (
            "atime",
            Mapping {
                set: false,
                val: unix::MS_NOATIME,
            },
        ),
        (
            "bind",
            Mapping {
                set: true,
                val: unix::MS_BIND,
            },
        ),
        ("defaults", Mapping { set: true, val: 0 }),
        (
            "dev",
            Mapping {
                set: false,
                val: unix::MS_NODEV,
            },
        ),
        (
            "diratime",
            Mapping {
                set: false,
                val: unix::MS_NODIRATIME,
            },
        ),
        (
            "dirsync",
            Mapping {
                set: true,
                val: unix::MS_DIRSYNC,
            },
        ),
        (
            "exec",
            Mapping {
                set: false,
                val: unix::MS_NOEXEC,
            },
        ),
        (
            "noexec",
            Mapping {
                set: true,
                val: unix::MS_NOEXEC,
            },
        ),
        (
            "iversion",
            Mapping {
                set: true,
                val: unix::MS_I_VERSION,
            },
        ),
        (
            "loud",
            Mapping {
                set: false,
                val: unix::MS_SILENT,
            },
        ),
        (
            "mand",
            Mapping {
                set: true,
                val: unix::MS_MANDLOCK,
            },
        ),
        (
            "noacl",
            Mapping {
                set: false,
                val: unix::MS_POSIXACL,
            },
        ),
        (
            "noatime",
            Mapping {
                set: true,
                val: unix::MS_NOATIME,
            },
        ),
        (
            "nodev",
            Mapping {
                set: true,
                val: unix::MS_NODEV,
            },
        ),
        (
            "nodiratime",
            Mapping {
                set: true,
                val: unix::MS_NODIRATIME,
            },
        ),
        (
            "noiversion",
            Mapping {
                set: false,
                val: unix::MS_I_VERSION,
            },
        ),
        (
            "nomand",
            Mapping {
                set: false,
                val: unix::MS_MANDLOCK,
            },
        ),
        (
            "norelatime",
            Mapping {
                set: false,
                val: unix::MS_RELATIME,
            },
        ),
        (
            "nostrictatime",
            Mapping {
                set: false,
                val: unix::MS_STRICTATIME,
            },
        ),
        (
            "nosuid",
            Mapping {
                set: true,
                val: unix::MS_NOSUID,
            },
        ),
        (
            "rbind",
            Mapping {
                set: true,
                val: unix::MS_BIND | unix::MS_REC,
            },
        ),
        (
            "relatime",
            Mapping {
                set: true,
                val: unix::MS_RELATIME,
            },
        ),
        (
            "remount",
            Mapping {
                set: true,
                val: unix::MS_REMOUNT,
            },
        ),
        (
            "ro",
            Mapping {
                set: true,
                val: unix::MS_RDONLY,
            },
        ),
        (
            "rw",
            Mapping {
                set: false,
                val: unix::MS_RDONLY,
            },
        ),
        (
            "silent",
            Mapping {
                set: true,
                val: unix::MS_SILENT,
            },
        ),
        (
            "strictatime",
            Mapping {
                set: true,
                val: unix::MS_STRICTATIME,
            },
        ),
        (
            "suid",
            Mapping {
                set: false,
                val: unix::MS_NOSUID,
            },
        ),
        (
            "sync",
            Mapping {
                set: true,
                val: unix::MS_SYNCHRONOUS,
            },
        ),
    ]
    .iter()
    .cloned()
    .collect()
});

static PROP_OPTIONS_MAP: Lazy<HashMap<&'static str, Mapping>> = Lazy::new(|| {
    [
        (
            "private",
            Mapping {
                set: true,
                val: unix::MS_PRIVATE,
            },
        ),
        (
            "rprivate",
            Mapping {
                set: true,
                val: unix::MS_PRIVATE | unix::MS_REC,
            },
        ),
        (
            "slave",
            Mapping {
                set: true,
                val: unix::MS_SLAVE,
            },
        ),
        (
            "rslave",
            Mapping {
                set: true,
                val: unix::MS_SLAVE | unix::MS_REC,
            },
        ),
        (
            "unbindable",
            Mapping {
                set: true,
                val: unix::MS_UNBINDABLE,
            },
        ),
        (
            "runbindable",
            Mapping {
                set: true,
                val: unix::MS_UNBINDABLE | unix::MS_REC,
            },
        ),
    ]
    .iter()
    .cloned()
    .collect()
});

fn options_to_flags(opts: Vec<&str>, source: &Lazy<HashMap<&str, Mapping>>) -> i32 {
    let mut rv = 0;
    for opt in opts {
        if let Some(m) = source.get(&opt) {
            if m.set {
                rv |= m.val;
            } else {
                rv ^= m.val;
            }
        }
    }
    rv
}

fn validate_rootfs_propagation(opt: &str) -> Result<(), &str> {
    let flags = options_to_flags(vec![opt], &PROP_OPTIONS_MAP);
    if flags & (unix::MS_SLAVE | unix::MS_PRIVATE) == 0 {
        Err("root mount propagation option must specify private or slave.")
    } else {
        validate_propagation(opt.clone())
    }
}

fn validate_propagation(opt: &str) -> Result<(), &str> {
    let flags = options_to_flags(vec![opt], &PROP_OPTIONS_MAP);
    let exclusive =
        flags & (unix::MS_SLAVE | unix::MS_PRIVATE | unix::MS_SHARED | unix::MS_UNBINDABLE);
    if exclusive.count_ones() > 1 {
        Err("mount propagation options are mutually exclusive.")
    } else {
        Ok(())
    }
}

fn validate_mount(mnt: &Mount) -> Result<(), &str> {
    if !Path::new(&mnt.destination).is_absolute() {
        return Err("Mount.destination must be an absolute path.");
    }
    if let Some(typ) = &mnt.typ {
        if typ == "bind" {
            return validate_mount_options(mnt.options.clone());
        }
    }
    Ok(())
}

fn validate_mount_options<'a>(opts: Option<Vec<String>>) -> Result<(), &'a str> {
    const INVALID_OPTIONS: [&str; 2] = ["shared", "rshared"];
    if let Some(opts) = opts {
        for opt in opts {
            if INVALID_OPTIONS.contains(&opt.as_str()) {
                return Err("mount option is not supported.");
            }
            if !OPTIONS_MAP.contains_key(&opt.as_str())
                && !PROP_OPTIONS_MAP.contains_key(&opt.as_str())
            {
                return Err("unknown mount option");
            }
            if let Err(e) = validate_propagation(&opt) {
                eprintln!("{}", e);
                return Err("invalid propagation.");
            }
        }
    }
    Ok(())
}

enum ContainerType {
    Unspecified,
    Unknown,
    Sandbox,
    Container,
}

static CONTAINERD_CONTAINER_TYPE_ANNOTATION: &'static str = "io.kubernetes.cri.container-type";
static CONTAINERD_SANDBOX_ID_ANNOTATION: &'static str = "io.kubernetes.cri.sandbox-id";
static CRIO_SANDBOX_ID_ANNOTATION: &'static str = "io.kubernetes.cri-o.SandboxID";
static CRIO_CONTAINER_TYPE_ANNOTATION: &'static str = "io.kubernetes.cri-o.ContainerType";

fn spec_container_type(spec: &Spec) -> ContainerType {
    const SANDBOX: &str = "sandbox";
    const CONTAINER: &str = "container";

    match &spec.annotations {
        Some(annotations) => {
            match annotations
                .get(CONTAINERD_CONTAINER_TYPE_ANNOTATION)
                .or(annotations.get(CRIO_CONTAINER_TYPE_ANNOTATION))
            {
                Some(t) => match t.as_str() {
                    SANDBOX => ContainerType::Sandbox,
                    CONTAINER => ContainerType::Container,
                    _ => ContainerType::Unknown,
                },
                None => ContainerType::Unspecified,
            }
        }
        None => ContainerType::Unspecified,
    }
}

fn sandbox_id(spec: &Spec) -> Option<String> {
    if let Some(annotations) = &spec.annotations {
        if let Some(id) = annotations.get(CONTAINERD_SANDBOX_ID_ANNOTATION) {
            return Some(id.clone());
        }
        if let Some(id) = annotations.get(CRIO_SANDBOX_ID_ANNOTATION) {
            return Some(id.clone());
        }
    }
    None
}

pub fn is_supported_dev_mount(m: &Mount) -> bool {
    let dst = m.destination.clone();
    // JOETODO: canonicalize() is not supported on this platform.
    // let dst = Path::new(&dst).canonicalize().unwrap();
    let existing_devices = [
        "/dev/fd",
        "/dev/stdin",
        "/dev/stdout",
        "/dev/stderr",
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/shm",
        "/dev/ptmx",
    ];
    existing_devices.iter().all(|&dev| {
        let dst = dst.as_str();
        dst != dev && !dst.starts_with(&format!("{}/", dev))
    })
}

// corresponds to Is9PMount() in gVisor.
pub fn is_external_mount(m: &Mount) -> bool {
    m.typ == Some("bind".to_string())
        && m.source.is_some()
        && m.source != Some("".to_string())
        && is_supported_dev_mount(m)
}
