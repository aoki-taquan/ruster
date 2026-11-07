//! `PacketSlot::truncate`: a frame cut to its first bytes is sent as cut.

use ruster_core::{IfId, PacketBatch, PacketIo};
use ruster_io_sim::SimIo;

const PORT: IfId = IfId(0);

fn send_after(cut: usize, frame: Vec<u8>) -> (bool, Vec<u8>) {
    let mut io = SimIo::new();
    io.inject(PORT, frame);
    let mut batch = io.receive(4).unwrap();
    let mut packet = batch.next_packet().expect("one frame");
    let cut_ok = packet.truncate(cut);
    packet.commit(PORT);
    drop(batch);
    (cut_ok, io.pop_tx().expect("sent").bytes)
}

#[test]
fn a_frame_is_sent_as_cut() {
    let frame: Vec<u8> = (0..60).collect();
    let (cut, sent) = send_after(40, frame.clone());
    assert!(cut);
    assert_eq!(sent, frame[..40]);
}

#[test]
fn cutting_to_the_same_length_keeps_the_frame() {
    let frame: Vec<u8> = (0..60).collect();
    let (cut, sent) = send_after(60, frame.clone());
    assert!(cut);
    assert_eq!(sent, frame);
}

#[test]
fn a_longer_or_empty_cut_is_refused_and_changes_nothing() {
    let frame: Vec<u8> = (0..60).collect();
    for len in [0, 61, 1000] {
        let (cut, sent) = send_after(len, frame.clone());
        assert!(!cut, "len {len}");
        assert_eq!(sent, frame, "len {len}");
    }
}
