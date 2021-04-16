pub const AF_UNIX: i32 = 0x1;

pub const MS_PRIVATE: i32 = 0x40000;
pub const MS_REC: i32 = 0x4000;
pub const MS_SLAVE: i32 = 0x80000;
pub const MS_UNBINDABLE: i32 = 0x20000;
pub const MS_SHARED: i32 = 0x100000;
pub const MS_POSIXACL: i32 = 0x10000;
pub const MS_SYNCHRONOUS: i32 = 0x10;
pub const MS_NOATIME: i32 = 0x400;
pub const MS_BIND: i32 = 0x1000;
pub const MS_NODEV: i32 = 0x4;
pub const MS_NODIRATIME: i32 = 0x800;
pub const MS_DIRSYNC: i32 = 0x80;
pub const MS_NOEXEC: i32 = 0x8;
pub const MS_I_VERSION: i32 = 0x800000;
pub const MS_SILENT: i32 = 0x8000;
pub const MS_MANDLOCK: i32 = 0x40;
pub const MS_RELATIME: i32 = 0x200000;
pub const MS_STRICTATIME: i32 = 0x1000000;
pub const MS_NOSUID: i32 = 0x2;
pub const MS_REMOUNT: i32 = 0x20;
pub const MS_RDONLY: i32 = 0x1;

pub const O_LARGEFILE: i32 = 0x0;
pub const O_RDONLY: i32 = 0x0;
pub const O_DIRECTORY: i32 = 0x10000;
pub const O_NONBLOCK: i32 = 0x800;
pub const O_PATH: i32 = 0x200000;
pub const O_NOFOLLOW: i32 = 0x20000;
pub const O_CLOEXEC: i32 = 0x80000;
pub const O_TRUNC: i32 = 0x200;
pub const O_ACCMODE: i32 = 0x3;
pub const O_CREAT: i32 = 0x40;
pub const O_EXCL: i32 = 0x80;

pub const SYS_READ: i32 = 0;
pub const SYS_WRITE: i32 = 1;
pub const SYS_CLOSE: i32 = 3;
pub const SYS_FSTAT: i32 = 5;
pub const SYS_LSEEK: i32 = 8;
pub const SYS_MMAP: i32 = 9;
pub const SYS_MPROTECT: i32 = 10;
pub const SYS_MUNMAP: i32 = 11;
pub const SYS_RT_SIGACTION: i32 = 13;
pub const SYS_RT_SIGPROCMASK: i32 = 14;
pub const SYS_RT_SIGRETURN: i32 = 15;
pub const SYS_PREAD64: i32 = 17;
pub const SYS_PWRITE64: i32 = 18;
pub const SYS_SCHED_YIELD: i32 = 24;
pub const SYS_MADVISE: i32 = 28;
pub const SYS_DUP: i32 = 32;
pub const SYS_NANOSLEEP: i32 = 35;
pub const SYS_GETPID: i32 = 39;
pub const SYS_SOCKET: i32 = 41;
pub const SYS_CONNECT: i32 = 42;
pub const SYS_ACCEPT: i32 = 43;
pub const SYS_SENDMSG: i32 = 46;
pub const SYS_RECVMSG: i32 = 47;
pub const SYS_SHUTDOWN: i32 = 48;
pub const SYS_SOCKETPAIR: i32 = 53;
pub const SYS_EXIT: i32 = 60;
pub const SYS_FCNTL: i32 = 72;
pub const SYS_FSYNC: i32 = 74;
pub const SYS_FTRUNCATE: i32 = 77;
pub const SYS_FCHMOD: i32 = 91;
pub const SYS_GETTIMEOFDAY: i32 = 96;
pub const SYS_SIGALTSTACK: i32 = 131;
pub const SYS_FSTATFS: i32 = 138;
pub const SYS_MLOCK: i32 = 149;
pub const SYS_GETTID: i32 = 186;
pub const SYS_FUTEX: i32 = 202;
pub const SYS_GETDENTS64: i32 = 217;
pub const SYS_RESTART_SYSCALL: i32 = 219;
pub const SYS_CLOCK_GETTIME: i32 = 228;
pub const SYS_EXIT_GROUP: i32 = 231;
pub const SYS_EPOLL_CTL: i32 = 233;
pub const SYS_TGKILL: i32 = 234;
pub const SYS_OPENAT: i32 = 257;
pub const SYS_MKDIRAT: i32 = 258;
pub const SYS_MKNODAT: i32 = 259;
pub const SYS_FCHOWNAT: i32 = 260;
pub const SYS_UNLINKAT: i32 = 263;
pub const SYS_RENAMEAT: i32 = 264;
pub const SYS_LINKAT: i32 = 265;
pub const SYS_SYMLINKAT: i32 = 266;
pub const SYS_READLINKAT: i32 = 267;
pub const SYS_PPOLL: i32 = 271;
pub const SYS_UTIMENSAT: i32 = 280;
pub const SYS_EPOLL_PWAIT: i32 = 281;
pub const SYS_FALLOCATE: i32 = 285;
pub const SYS_EVENTFD2: i32 = 290;
pub const SYS_GETCPU: i32 = 309;
pub const SYS_GETRANDOM: i32 = 318;
pub const SYS_MEMFD_CREATE: i32 = 319;

pub const F_ADD_SEALS: i32 = 0x409;
pub const F_GETFD: i32 = 0x1;
pub const F_GETFL: i32 = 0x3;
pub const F_SETFL: i32 = 0x4;

pub const MAP_SHARED: i32 = 0x1;
pub const MAP_PRIVATE: i32 = 0x2;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_FIXED: i32 = 0x10;

pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_TRUNC: i32 = 0x20;
pub const MSG_PEEK: i32 = 0x2;
pub const MSG_NOSIGNAL: i32 = 0x4000;

pub const SHUT_RDWR: i32 = 0x2;

pub const SOCK_STREAM: i32 = 0x1;
pub const SOCK_DGRAM: i32 = 0x2;
pub const SOCK_SEQPACKET: i32 = 0x5;
pub const SOCK_CLOEXEC: i32 = 0x80000;

pub const ENOENT: i32 = 0x2;
pub const EBADF: i32 = 0x9;
pub const EISDIR: i32 = 0x15;
pub const EINVAL: i32 = 0x16;
pub const ENOSYS: i32 = 0x26;
pub const EROFS: i32 = 0x1e;
pub const EBUSY: i32 = 0x10;
pub const EACCESS: i32 = 0xd;
pub const EIO: i32 = 0x5;

pub const S_IFMT: i32 = 0xf000;

pub const UTIME_NOW: i32 = 0x3fffffff;
pub const UTIME_OMIT: i32 = 0x3ffffffe;
