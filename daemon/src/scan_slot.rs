// daemon/src/scan_slot.rs — v1.1.0 — Thursday 12 November 2026
// One clamscan run at a time, machine-wide.
//
// Each clamscan run loads the whole signature database (~1 GB, 12–15 s), so two
// at once would double the memory. Inside the daemon a priority slot decides who
// goes next: an install scan (someone is waiting at a terminal) is served before
// a Downloads batch whenever the slot frees up. A batch already running is never
// interrupted. Across processes (the install worker), the file lock in
// `clam::acquire_scan_lock` keeps runs from overlapping.
//
// Blocking: call only from blocking threads (spawn_blocking / std threads).

use ghost_sentri_core::clam::{acquire_scan_lock, ScanLock};
use std::sync::{Condvar, Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// apt hook / install path — served first.
    Install,
    /// Downloads watch.
    Background,
}

#[derive(Default)]
struct State {
    busy: bool,
    install_waiting: usize,
}

fn slot() -> &'static (Mutex<State>, Condvar) {
    static SLOT: OnceLock<(Mutex<State>, Condvar)> = OnceLock::new();
    SLOT.get_or_init(|| (Mutex::new(State::default()), Condvar::new()))
}

/// Held for the duration of one clamscan run.
pub struct SlotGuard {
    _lock: ScanLock,
}

/// Wait for the slot, then for the cross-process lock.
pub fn acquire(p: Priority) -> SlotGuard {
    let (m, c) = slot();
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    match p {
        Priority::Install => {
            st.install_waiting += 1;
            while st.busy {
                st = c.wait(st).unwrap_or_else(|e| e.into_inner());
            }
            st.install_waiting -= 1;
        }
        Priority::Background => {
            while st.busy || st.install_waiting > 0 {
                st = c.wait(st).unwrap_or_else(|e| e.into_inner());
            }
        }
    }
    st.busy = true;
    drop(st);
    SlotGuard {
        _lock: acquire_scan_lock(),
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let (m, c) = slot();
        let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
        st.busy = false;
        drop(st);
        c.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn install_jumps_the_queue() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let g = acquire(Priority::Background);
        let o1 = order.clone();
        let bg = std::thread::spawn(move || {
            let _g = acquire(Priority::Background);
            o1.lock().unwrap().push("background");
        });
        std::thread::sleep(Duration::from_millis(50));
        let o2 = order.clone();
        let inst = std::thread::spawn(move || {
            let _g = acquire(Priority::Install);
            o2.lock().unwrap().push("install");
        });
        std::thread::sleep(Duration::from_millis(50));
        drop(g);
        bg.join().unwrap();
        inst.join().unwrap();
        assert_eq!(*order.lock().unwrap(), vec!["install", "background"]);
    }
}
