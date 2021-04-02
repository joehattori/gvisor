use crate::filter::SyscallRules;
use crate::linux;

// TODO: do we need this?
pub fn install<'a>(rules: &SyscallRules) -> Result<(), &'a str> {
    let default_action = default_action()?;
    println!(
        "Installing seccomp filters for {} syscalls (action={})",
        rules.len(),
        default_action
    );
    Ok(())
}

fn default_action<'a>() -> Result<i32, &'a str> {
    let available = is_kill_process_available()?;
    if available {
        Ok(linux::SECCOMP_RET_KILL_PROCESS)
    } else {
        Ok(linux::SECCOMP_RET_TRAP)
    }
}

// TODO: dummy for now. Need to look in seccomp for wasm32-wasi.
fn is_kill_process_available<'a>() -> Result<bool, &'a str> {
    Ok(false)
}
