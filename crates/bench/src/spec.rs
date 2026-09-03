//! Compiled identity for the canonical R17 benchmark specification.
//!
//! The hexadecimal string is generated from the complete canonical document
//! and is checked against it by repository scripts and unit tests. Runtime
//! packet processing uses only the typed digest; it never reads or hashes the
//! document.

use crate::Sha256Digest;

/// Lowercase SHA-256 of the exact bytes in `docs/benchmark-spec-v0.2.md`.
pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([
    0x57, 0x37, 0x20, 0xcd, 0xe7, 0xbb, 0xd5, 0x22, 0xee, 0x8f, 0x54, 0x86, 0x8b, 0x41, 0xbb, 0xf2,
    0x5e, 0xee, 0x9e, 0x3c, 0xb2, 0x27, 0xa9, 0x45, 0x53, 0xb5, 0x44, 0x11, 0xe1, 0x20, 0xde, 0x9d,
]);

/// String form used by cold-path artifact serialization and CI evidence.
pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str =
    "573720cde7bbd522ee8f54868b41bbf25eee9e3cb227a94553b54411e120de9d";

/// Returns the compiled R17 specification identity for downstream binding.
#[must_use]
pub const fn r17_benchmark_spec_sha256() -> Sha256Digest {
    R17_BENCHMARK_SPEC_SHA256
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AfxdpMode, DirectionProfile, HardwareCase, HardwareFrame, HardwarePlanClass,
        ServiceProfile, TransportProfile,
    };
    use std::collections::BTreeMap;

    const CANONICAL_SPEC_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/benchmark-spec-v0.2.md"
    ));

    #[test]
    fn canonical_spec_is_complete_and_has_exact_byte_shape() {
        assert!(std::str::from_utf8(CANONICAL_SPEC_BYTES).is_ok());
        assert!(!CANONICAL_SPEC_BYTES.starts_with(&[0xef, 0xbb, 0xbf]));
        assert!(!CANONICAL_SPEC_BYTES.contains(&b'\r'));
        assert!(CANONICAL_SPEC_BYTES.ends_with(b"\n"));
        assert!(!CANONICAL_SPEC_BYTES.ends_with(b"\n\n"));

        let text = std::str::from_utf8(CANONICAL_SPEC_BYTES).unwrap();
        for required in [
            "# R17 benchmark specification v0.2",
            "## Canonical byte contract",
            "## R17 deterministic smoke boundary",
            "## Hardware qualification boundary",
            "R17_BENCHMARK_SPEC_SHA256_HEX",
            "ruster.benchmark-smoke/v1",
            "forwarded-wire-exact",
            "spec_git_sha",
            "source_git_sha",
            "case_count",
            "logical_time_ms",
            "counter_allocations",
            "counter_received",
            "counter_tx_accepted",
            "counter_tx_rejected",
            "completion",
            "oracle",
        ] {
            assert!(
                text.contains(required),
                "missing canonical section/value: {required}"
            );
        }
        for case in crate::deterministic::R17_DETERMINISTIC_SMOKE_CASES {
            assert!(text.contains(case), "missing deterministic case: {case}");
        }
        let case_marker = "The exact 24 cases are:\n\n```text\n";
        let case_start = text.find(case_marker).unwrap() + case_marker.len();
        let case_end = text[case_start..].find("\n```\n").unwrap() + case_start;
        let listed_cases = text[case_start..case_end].lines().collect::<Vec<_>>();
        assert_eq!(
            listed_cases,
            crate::deterministic::R17_DETERMINISTIC_SMOKE_CASES.to_vec()
        );
        assert!(!text.contains(R17_BENCHMARK_SPEC_SHA256_HEX));
    }

    #[test]
    fn canonical_spec_binds_artifact_schema_and_hardware_plan_contract() {
        let text = std::str::from_utf8(CANONICAL_SPEC_BYTES).unwrap();
        let header_start = text
            .find("{\"artifact_schema\":\"ruster.benchmark-smoke/v1\",\"case_count\":24")
            .unwrap();
        let header_end = text[header_start..].find('\n').unwrap() + header_start;
        assert_eq!(
            json_keys(&text[header_start..header_end]),
            crate::deterministic::R17_DETERMINISTIC_SMOKE_HEADER_FIELDS.to_vec()
        );

        let case_start = text
            .find("{\"artifact_schema\":\"ruster.benchmark-smoke/v1\",\"case\":\"<case>\"")
            .unwrap();
        let case_end = text[case_start..].find('\n').unwrap() + case_start;
        assert_eq!(
            json_keys(&text[case_start..case_end]),
            crate::deterministic::R17_DETERMINISTIC_SMOKE_CASE_FIELDS.to_vec()
        );

        assert!(text.contains("`0x7508ce5cf2cb672e`"));
        assert!(text.contains("frame     = [eth64, eth128, eth512, ip-mtu1500, ruster-imix-v1]"));
        assert!(text.contains("direction = [outbound, inbound, bidirectional]"));
        assert!(text.contains("service   = [plain, nat44, nat44-firewall]"));
        assert!(text.contains("transport = [udp-checksum, tcp-checksum]"));
        for binding in [
            "The primary product is `frame × direction × service × transport`",
            "with mode `zero-copy`, queue `4`, batch `64`, and flow `4096`.",
            "are emitted in this order: `flow-one`, `flow64-imix`, `single-queue`,",
            "`copy-mode`, `standalone-firewall`, `udp-zero`, `batch-sweep`.",
            "nest frame, direction, service in that order;",
            "`flow64-imix` fixes `ruster-imix-v1` and nests direction, service.",
            "firewall nests frame, direction, transport.",
            "UDP-zero nests the four profiles",
            "before frame and direction; batch-sweep uses `[1, 32, 256]` in that order.",
            "The resulting control counts are `27 + 9 + 27 + 27 + 18 + 36 + 3 = 147`.",
        ] {
            assert!(
                text.contains(binding),
                "missing hardware binding: {binding}"
            );
        }
        assert_in_order(
            text,
            [
                "Control slices",
                "flow-one",
                "flow64-imix",
                "single-queue",
                "copy-mode",
                "standalone-firewall",
                "udp-zero",
                "batch-sweep",
            ],
        );
        assert!(text.contains(
            "The ordered `ruster-imix-v1` cycle is exactly seven `eth64`, four `eth512`,"
        ));
        assert!(text.contains("with cycle L1 size `4254` bytes."));
        assert_eq!(crate::HARDWARE_PLAN_VERSION, 1);
        assert_eq!(crate::HARDWARE_PRIMARY_CASE_COUNT, 90);
        assert_eq!(crate::HARDWARE_CONTROL_CASE_COUNT, 147);
        assert_eq!(crate::HARDWARE_TOTAL_CASE_COUNT, 237);
        assert_eq!(crate::HARDWARE_PLAN_FINGERPRINT_V1, 0x7508_ce5c_f2cb_672e);
        for binding in [
            "(60,64,84)",
            "(124,128,148)",
            "(508,512,532)",
            "(1514,1518,1538)",
            "10000000000",
            "2500000000/709",
            "3526093",
        ] {
            assert!(
                text.contains(binding),
                "missing wire known answer: {binding}"
            );
        }
    }

    #[test]
    fn structured_r17_binding_is_unique_and_matches_live_hardware_plan() {
        let text = std::str::from_utf8(CANONICAL_SPEC_BYTES).unwrap();
        let binding = parse_binding_block(text);
        for (key, expected) in [
            (
                "deterministic_workload_fingerprint",
                "0x6920d8872e7e5c38",
            ),
            (
                "deterministic_topology",
                "lan-if1/mac-020000000001;wan-if2/mac-020000000002;route-10.0.0.0/24-lan;route-0.0.0.0/0-wan-via-203.0.113.1;neighbor-lan-10.0.0.10-02000000000a;neighbor-wan-203.0.113.1-020000000014;binding-lan-10.0.0.1;binding-wan-203.0.113.10",
            ),
            (
                "deterministic_flow_tuples",
                "out-10.0.0.10:40000-198.51.100.20:443;in-198.51.100.20:443-10.0.0.10:40000",
            ),
            (
                "deterministic_packet_fixture",
                "wire64/backend60/ipv4-total46/ethernet14/ttl64/payload-xorshift64-shift13-7-17/all-case-and-setup-bytes-bound",
            ),
            (
                "deterministic_nat_policy",
                "udp-inside-lan-outside-wan-public-203.0.113.10-ports-40000-40000-idle-300000;tcp-inside-lan-outside-wan-public-203.0.113.10-ports-40000-40000-idle-7440000",
            ),
            (
                "deterministic_firewall_policy",
                "lan-to-wan-source-10.0.0.0/24-destination-any-udp-tcp-ports-any-allow-stateful-generation1-idle-300000-240000-7440000",
            ),
            (
                "deterministic_setup",
                "plain-measured-only;udp-udp-setup-then-measured;tcp-syn-syn-ack-ack-then-measured;event-order-udp-setup|tcp-syn|tcp-syn-ack|tcp-ack",
            ),
            (
                "deterministic_setup_known_answer",
                "fnv1a64/outputs-30/bytes-1800/output-68e9f945eb0b4571/order-ae892a47c58cc77a/semantic-markers-48fcc51ed2254b9c",
            ),
            (
                "deterministic_state",
                "nat-one-mapping-one-peer-or-session;firewall-one-state;combined-both;forward-one-tx-zero-drop-zero-timed-allocation",
            ),
            (
                "deterministic_flow_hash",
                "siphash-2-4-flow-tuple-domain-separated-key-not-emitted",
            ),
            (
                "deterministic_hash_role_mapping",
                "fnv1a64/2b07c91e57d31ca7/nat-udp-mapping-peer>nat-tcp-mapping-session>firewall-stateful-flow",
            ),
            (
                "deterministic_hash_constructor_binding",
                "actual-runtime-probe-v1/udp-nat44-mapping-peer/4-peers/Nat44UdpHashKey-new(mapping,peer)/74c7bdf39f779845|tcp-nat44-mapping-session/4-sessions/Nat44TcpHashKey-new(mapping,session)/ce7d6c21d5464308|firewall-stateful-flow/3-states/FirewallHashKey-new(flow)/a2b007540a6ff5cd|aggregate/8ee009f1015aef75",
            ),
            ("hardware_plan_version", "1"),
            ("hardware_plan_fingerprint", "0x7508ce5cf2cb672e"),
            (
                "hardware_normative_descriptor_fingerprint",
                "0xaa9bad5f9e6d8be7",
            ),
            ("hardware_primary_case_count", "90"),
            ("hardware_control_case_count", "147"),
            ("hardware_total_case_count", "237"),
            (
                "hardware_primary_product",
                "frame>direction>service>transport",
            ),
            (
                "hardware_primary_settings",
                "mode-zero-copy|queue-4|batch-64|flow-4096",
            ),
            (
                "hardware_primary_frames",
                "eth64|eth128|eth512|ip-mtu1500|ruster-imix-v1",
            ),
            (
                "hardware_primary_directions",
                "outbound|inbound|bidirectional",
            ),
            (
                "hardware_primary_services",
                "plain|nat44|nat44-firewall",
            ),
            (
                "hardware_primary_transports",
                "udp-checksum|tcp-checksum",
            ),
            (
                "hardware_control_frames",
                "eth64|eth512|ip-mtu1500",
            ),
            (
                "hardware_control_slice_order",
                "flow-one|flow64-imix|single-queue|copy-mode|standalone-firewall|udp-zero|batch-sweep",
            ),
            (
                "hardware_control_nesting",
                "flow-one:frame>direction>service|flow64-imix:direction>service|single-queue:frame>direction>service|copy-mode:frame>direction>service|standalone-firewall:frame>direction>transport|udp-zero:profile>frame>direction|batch-sweep:value",
            ),
            (
                "hardware_udp_zero_profiles",
                "zero-copy/q4/f1|zero-copy/q4/f64|zero-copy/q1/f4096|copy/q4/f4096",
            ),
            ("hardware_batch_sweep_values", "1|32|256"),
            ("hardware_control_counts", "27|9|27|27|18|36|3"),
            (
                "hardware_imix_cycle",
                "eth64|eth64|eth64|eth64|eth64|eth64|eth64|eth512|eth512|eth512|eth512|ip-mtu1500",
            ),
            ("hardware_imix_counts", "7|4|1"),
            ("hardware_imix_cycle_l1_bytes", "4254"),
            ("hardware_fixed_backend_bytes", "60|124|508|1514"),
            (
                "hardware_fixed_ethernet_bytes_including_fcs",
                "64|128|512|1518",
            ),
            (
                "hardware_fixed_l1_bytes_with_preamble_ifg",
                "84|148|532|1538",
            ),
            ("hardware_reference_line_rate_bps", "10000000000"),
            (
                "hardware_rate_formulas",
                "fixed-bps/(l1-bytes*8)|imix-bps*cycle-packets/(cycle-l1-bytes*8)",
            ),
        ] {
            assert_eq!(binding.get(key).copied(), Some(expected), "binding field {key}");
        }

        assert_eq!(
            crate::matrix::r17_deterministic_workload_fingerprint(),
            crate::R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT
        );
        let plan = crate::hardware_plan_v1().unwrap();
        let expected_cases = expected_hardware_cases();
        assert_eq!(plan.version, 1);
        assert_eq!(plan.cases.len(), 237);
        assert_eq!(expected_cases.len(), plan.cases.len());
        for (ordinal, (planned, (expected_class, expected_case))) in
            plan.cases.iter().zip(expected_cases.iter()).enumerate()
        {
            assert_eq!(planned.ordinal, ordinal as u16);
            assert_eq!(planned.seed, ordinal as u64 + 1);
            assert_eq!(planned.class, *expected_class);
            assert_eq!(planned.case, *expected_case);
            assert_eq!(planned.case_id, expected_case.canonical_id());
        }
        assert_eq!(
            crate::RUSTER_IMIX_V1_CYCLE.map(HardwareFrame::label),
            [
                "eth64",
                "eth64",
                "eth64",
                "eth64",
                "eth64",
                "eth64",
                "eth64",
                "eth512",
                "eth512",
                "eth512",
                "eth512",
                "ip-mtu1500",
            ]
        );
        assert_eq!(
            crate::R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT,
            u64::from_str_radix(
                binding["deterministic_workload_fingerprint"]
                    .strip_prefix("0x")
                    .unwrap(),
                16
            )
            .unwrap()
        );
    }

    fn parse_binding_block(text: &str) -> BTreeMap<&str, &str> {
        const START: &str = "```ruster-r17-binding-v1\n";
        assert_eq!(text.matches(START).count(), 1);
        let after_start = text.split_once(START).unwrap().1;
        let (body, _) = after_start.split_once("\n```\n").unwrap();
        let mut fields = BTreeMap::new();
        for line in body.lines() {
            let (key, value) = line
                .split_once('=')
                .expect("binding field must have a value");
            assert!(!key.is_empty());
            assert!(!value.is_empty());
            assert!(
                fields.insert(key, value).is_none(),
                "duplicate binding field {key}"
            );
        }
        let expected_keys = [
            "deterministic_workload_fingerprint",
            "deterministic_topology",
            "deterministic_flow_tuples",
            "deterministic_packet_fixture",
            "deterministic_nat_policy",
            "deterministic_firewall_policy",
            "deterministic_setup",
            "deterministic_setup_known_answer",
            "deterministic_state",
            "deterministic_flow_hash",
            "deterministic_hash_role_mapping",
            "deterministic_hash_constructor_binding",
            "hardware_plan_version",
            "hardware_plan_fingerprint",
            "hardware_normative_descriptor_fingerprint",
            "hardware_primary_case_count",
            "hardware_control_case_count",
            "hardware_total_case_count",
            "hardware_primary_product",
            "hardware_primary_settings",
            "hardware_primary_frames",
            "hardware_primary_directions",
            "hardware_primary_services",
            "hardware_primary_transports",
            "hardware_control_frames",
            "hardware_control_slice_order",
            "hardware_control_nesting",
            "hardware_udp_zero_profiles",
            "hardware_batch_sweep_values",
            "hardware_control_counts",
            "hardware_imix_cycle",
            "hardware_imix_counts",
            "hardware_imix_cycle_l1_bytes",
            "hardware_fixed_backend_bytes",
            "hardware_fixed_ethernet_bytes_including_fcs",
            "hardware_fixed_l1_bytes_with_preamble_ifg",
            "hardware_reference_line_rate_bps",
            "hardware_rate_formulas",
        ];
        assert_eq!(fields.len(), expected_keys.len());
        for key in expected_keys {
            assert!(fields.contains_key(key), "missing binding field {key}");
        }
        fields
    }

    fn expected_hardware_cases() -> Vec<(HardwarePlanClass, HardwareCase)> {
        let primary_frames = [
            HardwareFrame::Eth64,
            HardwareFrame::Eth128,
            HardwareFrame::Eth512,
            HardwareFrame::Ipv4Mtu1500,
            HardwareFrame::RusterImixV1,
        ];
        let control_frames = [
            HardwareFrame::Eth64,
            HardwareFrame::Eth512,
            HardwareFrame::Ipv4Mtu1500,
        ];
        let directions = [
            DirectionProfile::Outbound,
            DirectionProfile::Inbound,
            DirectionProfile::Bidirectional,
        ];
        let services = [
            ServiceProfile::Plain,
            ServiceProfile::Nat44,
            ServiceProfile::Nat44Firewall,
        ];
        let transports = [TransportProfile::UdpChecksum, TransportProfile::TcpChecksum];
        let mut expected = Vec::new();
        let mut push = |class, case| expected.push((class, case));
        for frame in primary_frames {
            for direction in directions {
                for service in services {
                    for transport in transports {
                        push(
                            HardwarePlanClass::Primary,
                            hardware_case(
                                AfxdpMode::ZeroCopy,
                                4,
                                64,
                                frame,
                                4_096,
                                direction,
                                service,
                                transport,
                            ),
                        );
                    }
                }
            }
        }
        for frame in control_frames {
            for direction in directions {
                for service in services {
                    push(
                        HardwarePlanClass::FlowOne,
                        hardware_case(
                            AfxdpMode::ZeroCopy,
                            4,
                            64,
                            frame,
                            1,
                            direction,
                            service,
                            TransportProfile::UdpChecksum,
                        ),
                    );
                }
            }
        }
        for direction in directions {
            for service in services {
                push(
                    HardwarePlanClass::Flow64Imix,
                    hardware_case(
                        AfxdpMode::ZeroCopy,
                        4,
                        64,
                        HardwareFrame::RusterImixV1,
                        64,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
        for frame in control_frames {
            for direction in directions {
                for service in services {
                    push(
                        HardwarePlanClass::SingleQueue,
                        hardware_case(
                            AfxdpMode::ZeroCopy,
                            1,
                            64,
                            frame,
                            4_096,
                            direction,
                            service,
                            TransportProfile::UdpChecksum,
                        ),
                    );
                }
            }
        }
        for frame in control_frames {
            for direction in directions {
                for service in services {
                    push(
                        HardwarePlanClass::CopyMode,
                        hardware_case(
                            AfxdpMode::Copy,
                            4,
                            64,
                            frame,
                            4_096,
                            direction,
                            service,
                            TransportProfile::UdpChecksum,
                        ),
                    );
                }
            }
        }
        for frame in control_frames {
            for direction in directions {
                for transport in transports {
                    push(
                        HardwarePlanClass::StandaloneFirewall,
                        hardware_case(
                            AfxdpMode::ZeroCopy,
                            4,
                            64,
                            frame,
                            4_096,
                            direction,
                            ServiceProfile::Firewall,
                            transport,
                        ),
                    );
                }
            }
        }
        for (mode, queue_count, flow_count) in [
            (AfxdpMode::ZeroCopy, 4, 1),
            (AfxdpMode::ZeroCopy, 4, 64),
            (AfxdpMode::ZeroCopy, 1, 4_096),
            (AfxdpMode::Copy, 4, 4_096),
        ] {
            for frame in control_frames {
                for direction in directions {
                    push(
                        HardwarePlanClass::UdpZero,
                        hardware_case(
                            mode,
                            queue_count,
                            64,
                            frame,
                            flow_count,
                            direction,
                            ServiceProfile::Plain,
                            TransportProfile::UdpZero,
                        ),
                    );
                }
            }
        }
        for batch_size in [1, 32, 256] {
            push(
                HardwarePlanClass::BatchSweep,
                hardware_case(
                    AfxdpMode::ZeroCopy,
                    4,
                    batch_size,
                    HardwareFrame::RusterImixV1,
                    4_096,
                    DirectionProfile::Bidirectional,
                    ServiceProfile::Nat44Firewall,
                    TransportProfile::UdpChecksum,
                ),
            );
        }
        expected
    }

    #[allow(clippy::too_many_arguments)]
    fn hardware_case(
        mode: AfxdpMode,
        queue_count: u16,
        batch_size: u16,
        frame: HardwareFrame,
        flow_count: u32,
        direction: DirectionProfile,
        service: ServiceProfile,
        transport: TransportProfile,
    ) -> HardwareCase {
        HardwareCase {
            mode,
            queue_count,
            batch_size,
            frame,
            flow_count,
            direction,
            service,
            transport,
        }
    }

    #[test]
    fn compiled_identity_matches_the_complete_canonical_spec_bytes() {
        let digest = sha256(CANONICAL_SPEC_BYTES);
        assert_eq!(digest, *R17_BENCHMARK_SPEC_SHA256.as_bytes());
        assert_eq!(
            R17_BENCHMARK_SPEC_SHA256.to_lower_hex(),
            R17_BENCHMARK_SPEC_SHA256_HEX
        );
    }

    const SHA256_ROUND_CONSTANTS: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    fn sha256(input: &[u8]) -> [u8; 32] {
        let bit_len = u64::try_from(input.len()).unwrap() * 8;
        let padded_len = (input.len() + 9).div_ceil(64) * 64;
        let mut padded = vec![0_u8; padded_len];
        padded[..input.len()].copy_from_slice(input);
        padded[input.len()] = 0x80;
        padded[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

        let mut state: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        for chunk in padded.chunks_exact(64) {
            let mut words = [0_u32; 64];
            for (index, word) in words[..16].iter_mut().enumerate() {
                let offset = index * 4;
                *word = u32::from_be_bytes([
                    chunk[offset],
                    chunk[offset + 1],
                    chunk[offset + 2],
                    chunk[offset + 3],
                ]);
            }
            for index in 16..64 {
                let s0 = words[index - 15].rotate_right(7)
                    ^ words[index - 15].rotate_right(18)
                    ^ (words[index - 15] >> 3);
                let s1 = words[index - 2].rotate_right(17)
                    ^ words[index - 2].rotate_right(19)
                    ^ (words[index - 2] >> 10);
                words[index] = words[index - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[index - 7])
                    .wrapping_add(s1);
            }

            let mut working = state;
            for index in 0..64 {
                let sum1 = working[4].rotate_right(6)
                    ^ working[4].rotate_right(11)
                    ^ working[4].rotate_right(25);
                let choice = (working[4] & working[5]) ^ (!working[4] & working[6]);
                let temporary1 = working[7]
                    .wrapping_add(sum1)
                    .wrapping_add(choice)
                    .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                    .wrapping_add(words[index]);
                let sum0 = working[0].rotate_right(2)
                    ^ working[0].rotate_right(13)
                    ^ working[0].rotate_right(22);
                let majority = (working[0] & working[1])
                    ^ (working[0] & working[2])
                    ^ (working[1] & working[2]);
                let temporary2 = sum0.wrapping_add(majority);
                working[7] = working[6];
                working[6] = working[5];
                working[5] = working[4];
                working[4] = working[3].wrapping_add(temporary1);
                working[3] = working[2];
                working[2] = working[1];
                working[1] = working[0];
                working[0] = temporary1.wrapping_add(temporary2);
            }
            for (value, update) in state.iter_mut().zip(working) {
                *value = (*value).wrapping_add(update);
            }
        }

        let mut digest = [0_u8; 32];
        for (index, word) in state.into_iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn json_keys(line: &str) -> Vec<&str> {
        let mut keys = Vec::new();
        let mut cursor = 0;
        while let Some(relative_end) = line[cursor..].find("\":") {
            let end = cursor + relative_end;
            let start = line[..end].rfind('"').unwrap() + 1;
            keys.push(&line[start..end]);
            cursor = end + 2;
        }
        keys
    }

    fn assert_in_order(text: &str, terms: [&str; 8]) {
        let mut offset = 0;
        for term in terms {
            let relative = text[offset..]
                .find(term)
                .unwrap_or_else(|| panic!("missing ordered term: {term}"));
            offset += relative + term.len();
        }
    }
}
