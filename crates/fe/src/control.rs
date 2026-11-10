//! The datagram sockets to the control processes the punt table names (other than
//! the neighbor process, which has its own): DHCP, PPPoE and the like.
//!
//! With a socket directory set, the FE binds `fe/punt/<name>.sock` there for each
//! control process the classes name, sends to `<name>/punt.sock` and takes frames
//! back only from that path. A process that restarts binds its path again. A
//! process no class names any more loses its socket at the next table change.
//!
//! A control process may send back only the kinds of frame its classes give it:
//! PPPoE frames for a PPPoE class, IPv4 and IPv6 frames for an IP class. The FE
//! sends them out of the named interface as they are. The check is by Ethernet
//! type only: the interface, protocol and ports of the classes are not checked, so
//! a control process is trusted as much as the socket directory is.
//!
//! # Standards
//!
//! None: the messages are ruster's own ([`ruster_proto::punt`]).

use std::io::{self, ErrorKind};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

use ruster_proto::daemon::{self, socket};
use ruster_proto::punt::{reason, Direction, Punt};

/// One control process's socket and what it may send back.
struct Control {
    name: String,
    socket: UnixDatagram,
    /// `None` for a connected socket.
    peer: Option<PathBuf>,
    pppoe: bool,
    ip: bool,
}

#[derive(Default)]
pub(crate) struct Controls {
    dir: Option<PathBuf>,
    list: Vec<Control>,
    /// The control processes of the current tables, and what each may send back.
    wanted: Vec<(String, bool, bool)>,
    /// The message being sent, kept to be used again.
    message: Vec<u8>,
}

impl Controls {
    /// Binds the sockets under `dir` from the next table change.
    pub(crate) fn set_dir(&mut self, dir: PathBuf) {
        self.dir = Some(dir);
    }

    /// Uses the connected `socket` for control process `name` (for tests, and for a
    /// caller that sets the sockets up itself). The classes still decide what it
    /// may send back.
    pub(crate) fn attach(&mut self, name: &str, socket: UnixDatagram) -> io::Result<()> {
        socket.set_nonblocking(true)?;
        self.list.retain(|c| c.name != name);
        let (pppoe, ip) = self
            .wanted
            .iter()
            .find(|(n, ..)| n == name)
            .map_or((false, false), |&(_, pppoe, ip)| (pppoe, ip));
        self.list.push(Control {
            name: name.to_owned(),
            socket,
            peer: None,
            pppoe,
            ip,
        });
        Ok(())
    }

    /// Follows the control processes of new tables: (name, PPPoE frames, IP
    /// frames) for each.
    pub(crate) fn follow(&mut self, wanted: Vec<(String, bool, bool)>) {
        self.list
            .retain(|control| wanted.iter().any(|(name, ..)| *name == control.name));
        for (name, pppoe, ip) in &wanted {
            if let Some(control) = self.list.iter_mut().find(|c| c.name == *name) {
                control.pppoe = *pppoe;
                control.ip = *ip;
                continue;
            }
            let Some(dir) = &self.dir else {
                continue;
            };
            match daemon::bind_datagram(&dir.join(socket::fe_punt(name))) {
                Ok(bound) => self.list.push(Control {
                    name: name.clone(),
                    socket: bound,
                    peer: Some(dir.join(socket::control_punt(name))),
                    pppoe: *pppoe,
                    ip: *ip,
                }),
                // Tried again at the next table change.
                Err(error) => eprintln!("ruster-fe: {}: {error}", socket::fe_punt(name)),
            }
        }
        self.wanted = wanted;
    }

    /// Sends `frame` from `interface` to control process `name`; whether it went.
    pub(crate) fn send(&mut self, name: &str, why: u16, interface: &str, frame: &[u8]) -> bool {
        let Some(control) = self.list.iter().find(|c| c.name == name) else {
            return false;
        };
        self.message.clear();
        let encoded = Punt {
            direction: Direction::ToControl,
            reason: why,
            interface,
            frame,
        }
        .encode(&mut self.message);
        if encoded.is_err() {
            return false;
        }
        let sent = match &control.peer {
            Some(peer) => control.socket.send_to(&self.message, peer),
            None => control.socket.send(&self.message),
        };
        sent.is_ok()
    }

    /// The messages the control processes sent, at most `per_process` from each, as
    /// long as `max` bytes; `refused` counts those from a stranger or too long.
    pub(crate) fn receive(
        &self,
        per_process: usize,
        max: usize,
        refused: &mut u64,
    ) -> Vec<Vec<u8>> {
        let mut buf = vec![0_u8; max + 1];
        let mut got = Vec::new();
        for control in &self.list {
            for _ in 0..per_process {
                match control.socket.recv_from(&mut buf) {
                    Ok((_, from))
                        if control
                            .peer
                            .as_deref()
                            .is_some_and(|peer| from.as_pathname() != Some(peer)) =>
                    {
                        *refused += 1;
                    }
                    Ok((n, _)) if n <= max => {
                        let ok = Punt::decode(&buf[..n]).is_ok_and(|punt| allowed(control, &punt));
                        if ok {
                            got.push(buf[..n].to_vec());
                        } else {
                            *refused += 1;
                        }
                    }
                    Ok(_) => *refused += 1,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        got
    }
}

/// Whether `control` may have the FE send the frame of `punt`.
fn allowed(control: &Control, punt: &Punt<'_>) -> bool {
    let Some(ethertype) = punt.frame.get(12..14) else {
        return false;
    };
    punt.direction == Direction::FromControl
        && match punt.reason {
            reason::PPPOE_DISCOVERY => control.pppoe && ethertype == [0x88, 0x63],
            reason::PPP_CONTROL => control.pppoe && ethertype == [0x88, 0x64],
            reason::IP => control.ip && (ethertype == [0x08, 0x00] || ethertype == [0x86, 0xdd]),
            _ => false,
        }
}
