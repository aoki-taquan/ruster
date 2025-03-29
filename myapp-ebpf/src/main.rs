#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use packts::eth::{EthBaseHeader, EthFrame, RawEthFrame, ETH_BASE_HEADER_SIZE};

#[xdp]
pub fn myapp(ctx: XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();

    if end - start < ETH_BASE_HEADER_SIZE {
        return XDP_DROP;
    }
    let eth_base_header: *const EthBaseHeader = start as *const EthBaseHeader;
    let eth_base_header = unsafe { &*eth_base_header };

    let payload_start_pointer = start + ETH_BASE_HEADER_SIZE;
    let payload_length = end - payload_start_pointer;
    let payload_start_pointer: *const u8 = payload_start_pointer as *const u8;
    let payload = unsafe { core::slice::from_raw_parts(payload_start_pointer, payload_length) };

    let raw_eth_frame = RawEthFrame {
        base_header: eth_base_header,
        option_header_payload: payload,
    };

    let eth_frame: EthFrame = raw_eth_frame.try_into().unwrap();

    let src = eth_frame.base_header.source_address;
    info!(
        &ctx,
        "src: {}:{}:{}:{}:{}:{}", src[0], src[1], src[2], src[3], src[4], src[5]
    );

    XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
