const EXTERNAL_ADDRESS: u32 = 0x0A000002; //TODO

fn index_to_mape_port(index: u8) -> u16 {
    todo!()
}

mod tcp {
    use aya_ebpf::maps::{Array, HashMap};
    pub struct Nat44 {}
}

mod udp {
    use aya_ebpf::{
        macros::map,
        maps::{Array, HashMap},
        programs::XdpContext,
    };
    const UDP_TIMEOUT_SEC: u64 = 300;
    const UDP_TIMEOUT: u64 = UDP_TIMEOUT_SEC * 1000 * 1000 * 1000;

    #[map]
    static UDP_MAPE_NAT44_TRANSLATE_TABLE: Array<TranslateTableEntry> =
        Array::with_max_entries(240, 0);

    #[map]
    static UDP_MAPE_NAT44_REVERSE_TABLE: HashMap<ReverseTableKey, TranslateTableIndex> =
        HashMap::with_max_entries(240 * 2, 0);

    struct TranslateTableEntry {
        pub internal_address: u32,
        pub internal_port: u16,
        last_active: u64,
    }

    impl TranslateTableEntry {
        pub fn new(internal_address: u32, internal_port: u16) -> Self {
            Self {
                internal_address,
                internal_port,
                last_active: unsafe { aya_ebpf_bindings::helpers::bpf_ktime_get_coarse_ns() },
            }
        }

        pub fn update(&mut self) {
            self.last_active = unsafe { aya_ebpf_bindings::helpers::bpf_ktime_get_coarse_ns() };
        }

        pub fn is_expired(&self) -> bool {
            let now = unsafe { aya_ebpf_bindings::helpers::bpf_ktime_get_coarse_ns() };
            now - self.last_active > UDP_TIMEOUT
        }

        // internal_addressとinternal_portが一致するか
        pub fn is_match(&self, internal_address: u32, internal_port: u16) -> bool {
            self.internal_address == internal_address && self.internal_port == internal_port
        }
    }

    struct ReverseTableKey {
        pub internal_address: u32,
        pub internal_port: u8,
    }

    struct TranslateTableIndex(pub u16);

    pub fn translate_internal_to_external(ctx: &mut XdpContext) -> u16 {
        todo!()
    }

    pub fn translate_external_to_internal(ctx: &mut XdpContext) -> u16 {}
}
