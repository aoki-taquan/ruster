#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp]
pub fn myapp(ctx: XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();

    if end - start < ETH_BASE_HEADER_SIZE {
    }

    XDP_DROP
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
