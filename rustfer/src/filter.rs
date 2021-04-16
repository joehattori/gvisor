use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::linux;
use crate::seccomp;
use crate::unix;

#[derive(Clone, Copy)]
enum Rule {
    EqualTo(i32),
    MatchAny,

    Nil,
}

#[derive(Clone)]
pub struct Rules([Rule; 7]);

impl Rules {
    fn new(arr: &[Rule]) -> Self {
        let mut rules = [Rule::Nil; 7];
        for i in 0..arr.len() {
            rules[i] = arr[i];
        }
        Rules(rules)
    }
}

pub type SyscallRules = HashMap<i32, Vec<Rules>>;

pub fn install<'a>() -> Result<(), &'a str> {
    seccomp::install(&*ALLOWED_SYSCALL.lock().unwrap())
}

pub fn install_uds_filters() {
    let uds: SyscallRules = [
        (
            unix::SYS_SOCKET,
            vec![
                Rules::new(&[
                    Rule::EqualTo(unix::AF_UNIX),
                    Rule::EqualTo(unix::SOCK_STREAM),
                    Rule::EqualTo(0),
                ]),
                Rules::new(&[
                    Rule::EqualTo(unix::AF_UNIX),
                    Rule::EqualTo(unix::SOCK_DGRAM),
                    Rule::EqualTo(0),
                ]),
                Rules::new(&[
                    Rule::EqualTo(unix::AF_UNIX),
                    Rule::EqualTo(unix::SOCK_SEQPACKET),
                    Rule::EqualTo(0),
                ]),
            ],
        ),
        (unix::SYS_CONNECT, vec![Rules::new(&[Rule::MatchAny])]),
    ]
    .iter()
    .cloned()
    .collect();

    ALLOWED_SYSCALL.lock().unwrap().extend(uds);
}

static ALLOWED_SYSCALL: Lazy<Mutex<SyscallRules>> = Lazy::new(|| {
    Mutex::new(
        [
            (unix::SYS_ACCEPT, vec![]),
            (unix::SYS_CLOCK_GETTIME, vec![]),
            (unix::SYS_CLOSE, vec![]),
            (unix::SYS_DUP, vec![]),
            (unix::SYS_EPOLL_CTL, vec![]),
            (
                unix::SYS_EPOLL_PWAIT,
                vec![Rules::new(&[
                    Rule::MatchAny,
                    Rule::MatchAny,
                    Rule::MatchAny,
                    Rule::MatchAny,
                    Rule::EqualTo(0),
                ])],
            ),
            (
                unix::SYS_EVENTFD2,
                vec![Rules::new(&[Rule::EqualTo(0), Rule::EqualTo(0)])],
            ),
            (unix::SYS_EXIT, vec![]),
            (unix::SYS_EXIT_GROUP, vec![]),
            (
                unix::SYS_FALLOCATE,
                vec![Rules::new(&[Rule::MatchAny, Rule::EqualTo(0)])],
            ),
            (unix::SYS_FCHMOD, vec![]),
            (unix::SYS_FCHOWNAT, vec![]),
            (
                unix::SYS_FCNTL,
                vec![
                    Rules::new(&[Rule::MatchAny, Rule::EqualTo(unix::F_GETFL)]),
                    Rules::new(&[Rule::MatchAny, Rule::EqualTo(unix::F_SETFL)]),
                    Rules::new(&[Rule::MatchAny, Rule::EqualTo(unix::F_GETFD)]),
                    Rules::new(&[Rule::MatchAny, Rule::EqualTo(unix::F_ADD_SEALS)]),
                ],
            ),
            (unix::SYS_FSTAT, vec![]),
            (unix::SYS_FSTATFS, vec![]),
            (unix::SYS_FSYNC, vec![]),
            (unix::SYS_FTRUNCATE, vec![]),
            (
                unix::SYS_FUTEX,
                vec![
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::EqualTo(linux::FUTEX_WAIT | linux::FUTEX_PRIVATE_FLAG),
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(0),
                    ]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::EqualTo(linux::FUTEX_WAKE | linux::FUTEX_PRIVATE_FLAG),
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(0),
                    ]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::EqualTo(linux::FUTEX_WAIT),
                        Rule::MatchAny,
                        Rule::MatchAny,
                    ]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::EqualTo(linux::FUTEX_WAKE),
                        Rule::MatchAny,
                        Rule::MatchAny,
                    ]),
                ],
            ),
            (
                unix::SYS_GETCPU,
                vec![Rules::new(&[
                    Rule::MatchAny,
                    Rule::EqualTo(0),
                    Rule::EqualTo(0),
                ])],
            ),
            (unix::SYS_GETDENTS64, vec![]),
            (unix::SYS_GETPID, vec![]),
            (unix::SYS_GETRANDOM, vec![]),
            (unix::SYS_GETTID, vec![]),
            (unix::SYS_GETTIMEOFDAY, vec![]),
            (unix::SYS_LINKAT, vec![]),
            (unix::SYS_LSEEK, vec![]),
            (unix::SYS_MADVISE, vec![]),
            (unix::SYS_MEMFD_CREATE, vec![]),
            (unix::SYS_MKDIRAT, vec![]),
            (unix::SYS_MKNODAT, vec![]),
            (
                unix::SYS_MLOCK,
                vec![Rules::new(&[Rule::MatchAny, Rule::EqualTo(4096)])],
            ),
            (
                unix::SYS_MMAP,
                vec![
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(unix::MAP_SHARED),
                    ]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(unix::MAP_PRIVATE | unix::MAP_ANONYMOUS),
                    ]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(unix::MAP_PRIVATE | unix::MAP_ANONYMOUS | unix::MAP_FIXED),
                    ]),
                ],
            ),
            (unix::SYS_MPROTECT, vec![]),
            (unix::SYS_MUNMAP, vec![]),
            (unix::SYS_NANOSLEEP, vec![]),
            (unix::SYS_OPENAT, vec![]),
            (unix::SYS_PPOLL, vec![]),
            (unix::SYS_PREAD64, vec![]),
            (unix::SYS_PWRITE64, vec![]),
            (unix::SYS_READ, vec![]),
            (unix::SYS_READLINKAT, vec![]),
            (
                unix::SYS_RECVMSG,
                vec![
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(unix::MSG_DONTWAIT | unix::MSG_TRUNC),
                    ]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(unix::MSG_DONTWAIT | unix::MSG_TRUNC | unix::MSG_PEEK),
                    ]),
                ],
            ),
            (unix::SYS_RENAMEAT, vec![]),
            (unix::SYS_RESTART_SYSCALL, vec![]),
            (unix::SYS_RT_SIGACTION, vec![]),
            (unix::SYS_RT_SIGPROCMASK, vec![]),
            (unix::SYS_RT_SIGRETURN, vec![]),
            (unix::SYS_SCHED_YIELD, vec![]),
            (
                unix::SYS_SENDMSG,
                vec![
                    Rules::new(&[Rule::MatchAny, Rule::MatchAny, Rule::EqualTo(0)]),
                    Rules::new(&[
                        Rule::MatchAny,
                        Rule::MatchAny,
                        Rule::EqualTo(unix::MSG_DONTWAIT | unix::MSG_NOSIGNAL),
                    ]),
                ],
            ),
            (
                unix::SYS_SHUTDOWN,
                vec![Rules::new(&[
                    Rule::MatchAny,
                    Rule::EqualTo(unix::SHUT_RDWR),
                ])],
            ),
            (unix::SYS_SIGALTSTACK, vec![]),
            (
                unix::SYS_SOCKETPAIR,
                vec![Rules::new(&[
                    Rule::EqualTo(unix::AF_UNIX),
                    Rule::EqualTo(unix::SOCK_SEQPACKET),
                    Rule::EqualTo(unix::SOCK_CLOEXEC),
                ])],
            ),
            (unix::SYS_SYMLINKAT, vec![]),
            // (
            //     unix::SYS_TGKILL,
            //     // TODO: std::process::id() is not supported on wasm32-wasi.
            //     vec![Rules::new(&[Rule::EqualTo(std::process::id())])],
            // ),
            (unix::SYS_UNLINKAT, vec![]),
            (unix::SYS_UTIMENSAT, vec![]),
            (unix::SYS_WRITE, vec![]),
        ]
        .iter()
        .cloned()
        .collect(),
    )
});
