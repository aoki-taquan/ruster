#!/bin/sh
set -eu
set -f

usage()
{
    echo "usage: $0 [--duration-sec N] [--backend af_packet|af_xdp] [--sample-interval-sec N]" >&2
    exit 2
}

is_positive_decimal()
{
    case "$1" in
        ''|0*|*[!0123456789]*)
            return 1
            ;;
        [1-9]*)
            return 0
            ;;
    esac
    return 1
}

duration_sec=60
backend=af_packet
sample_interval_sec=5

while [ "$#" -gt 0 ]; do
    case "$1" in
        --duration-sec)
            [ "$#" -ge 2 ] || usage
            duration_sec=$2
            shift 2
            ;;
        --backend)
            [ "$#" -ge 2 ] || usage
            backend=$2
            shift 2
            ;;
        --sample-interval-sec)
            [ "$#" -ge 2 ] || usage
            sample_interval_sec=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

if ! is_positive_decimal "$duration_sec"; then
    echo "run-soak.sh: --duration-sec must be a positive decimal integer" >&2
    exit 2
fi
if ! is_positive_decimal "$sample_interval_sec"; then
    echo "run-soak.sh: --sample-interval-sec must be a positive decimal integer" >&2
    exit 2
fi
case "$backend" in
    af_packet)
        expected_backend_mode=af_packet_copy
        ;;
    af_xdp)
        expected_backend_mode=af_xdp
        ;;
    *)
        echo "run-soak.sh: --backend must be af_packet or af_xdp" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "run-soak.sh: must run as root to create network namespaces and veth links" >&2
    exit 1
fi

for command_name in awk cargo cat cp dirname echo env ethtool grep id ip kill mktemp ps pwd python3 rm sed sleep sysctl; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "run-soak.sh: required command not found: $command_name" >&2
        exit 1
    fi
done

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

echo "run-soak.sh: building ruster CLI with locked dependencies" >&2
cargo build -p ruster-cli --bin ruster --locked >&2
binary="$repo_root/target/debug/ruster"
if [ ! -x "$binary" ]; then
    echo "run-soak.sh: cargo build did not produce executable $binary" >&2
    exit 1
fi

workdir=$(mktemp -d)
config_path="$workdir/config.toml"
control_socket="$workdir/control.sock"
daemon_log="$workdir/daemon.log"
server_log="$workdir/server.log"
client_log="$workdir/client.log"
validate_log="$workdir/validate.log"
samples_path="$workdir/samples.tsv"
current_errors_path="$workdir/current-errors.tsv"
previous_errors_path="$workdir/previous-errors.tsv"
server_ready="$workdir/server.ready"
client_ready="$workdir/client.ready"

: >"$samples_path"
: >"$previous_errors_path"

suffix=$$
sender_ns="ruster-soak-s-$suffix"
daemon_ns="ruster-soak-d-$suffix"
receiver_ns="ruster-soak-r-$suffix"
sender_if="rss$suffix"
lan_if="rsl$suffix"
wan_if="rsw$suffix"
receiver_if="rsr$suffix"

sender_mac="02:00:00:00:00:04"
lan_mac="02:00:00:00:00:01"
wan_mac="02:00:00:00:00:02"
receiver_mac="02:00:00:00:00:03"

daemon_pid=
server_pid=
client_pid=
daemon_reaped=0
server_reaped=0
client_reaped=0
daemon_ns_created=0
process_deaths=0
sample_count=0
error_counter_total=missing
shutdown_rc=255
if [ "$backend" = af_xdp ]; then
    xdp_residual=not_checked
else
    xdp_residual=0
fi
final_printed=0
failures=none

forwarded_total=missing
forwarded_monotonic=false
rss_first_kib=missing
rss_last_kib=missing
rss_max_kib=missing
rss_slope_kib_per_min=missing
rss_slope_status=not_checked
fd_first=missing
fd_last=missing
fd_max=missing
threads_first=missing
threads_last=missing
threads_max=missing

add_failure()
{
    failure=$1
    case "$failure" in
        ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
            failure=invalid_failure_token
            ;;
    esac
    case "$failures" in
        none)
            failures=$failure
            ;;
        *,"$failure",*|"$failure",*|*,"$failure"|"$failure")
            ;;
        *)
            failures=$failures,$failure
            ;;
    esac
}

ns_exists()
{
    namespace=$1
    netns_list=$(ip netns list) || return 2
    printf '%s\n' "$netns_list" | awk -v wanted="$namespace" '$1 == wanted { found=1 } END { exit(found ? 0 : 1) }'
}

process_running()
{
    pid=$1
    state=$(ps -o stat= -p "$pid" 2>/dev/null | awk 'NF { print $1; exit }')
    case "$state" in
        ''|Z*)
            return 1
            ;;
    esac
    return 0
}

wait_for_process_exit()
{
    pid=$1
    limit=$2
    loops=0
    while process_running "$pid"; do
        if [ "$loops" -ge "$limit" ]; then
            return 1
        fi
        sleep 1
        loops=$((loops + 1))
    done
    return 0
}

mark_process_reaped()
{
    label=$1
    case "$label" in
        daemon)
            daemon_reaped=1
            ;;
        server|receiver_server)
            server_reaped=1
            ;;
        client|sender_client)
            client_reaped=1
            ;;
    esac
}

process_was_reaped()
{
    label=$1
    case "$label" in
        daemon)
            [ "$daemon_reaped" -eq 1 ]
            ;;
        server|receiver_server)
            [ "$server_reaped" -eq 1 ]
            ;;
        client|sender_client)
            [ "$client_reaped" -eq 1 ]
            ;;
        *)
            return 1
            ;;
    esac
}

stop_child()
{
    pid=$1
    label=$2
    [ -n "$pid" ] || return 0

    stop_rc=0
    if process_running "$pid"; then
        if ! kill -TERM "$pid" 2>/dev/null; then
            echo "run-soak.sh: failed to send SIGTERM to $label pid=$pid" >&2
            stop_rc=1
        fi

        if ! wait_for_process_exit "$pid" 10; then
            echo "run-soak.sh: $label pid=$pid did not stop after SIGTERM; sending SIGKILL" >&2
            stop_rc=1
            if ! kill -KILL "$pid" 2>/dev/null; then
                echo "run-soak.sh: failed to send SIGKILL to $label pid=$pid" >&2
            elif ! wait_for_process_exit "$pid" 5; then
                echo "run-soak.sh: $label pid=$pid is still running after SIGKILL" >&2
            fi
        fi
    fi

    if process_running "$pid"; then
        return 1
    fi
    wait "$pid" >/dev/null 2>&1 || :
    mark_process_reaped "$label"
    return "$stop_rc"
}

count_process_death()
{
    pid=$1
    label=$2
    failure=$3
    [ -n "$pid" ] || return 0
    if ! process_running "$pid"; then
        if process_was_reaped "$label"; then
            return 1
        fi
        process_deaths=$((process_deaths + 1))
        add_failure "$failure"
        echo "run-soak.sh: $label exited unexpectedly" >&2
        wait "$pid" >/dev/null 2>&1 || :
        mark_process_reaped "$label"
        return 1
    fi
    return 0
}

check_traffic_processes()
{
    traffic_check_rc=0
    count_process_death "$daemon_pid" daemon daemon_died_at_traffic_end || traffic_check_rc=1
    count_process_death "$server_pid" receiver_server server_died_at_traffic_end || traffic_check_rc=1
    count_process_death "$client_pid" sender_client client_died_at_traffic_end || traffic_check_rc=1
    return "$traffic_check_rc"
}

dump_log()
{
    path=$1
    label=$2
    if [ -f "$path" ]; then
        echo "run-soak.sh: $label log follows: $path" >&2
        sed -n '1,220p' "$path" >&2 || :
    fi
}

detach_xdp()
{
    namespace=$1
    interface=$2
    if ns_exists "$namespace"; then
        if ! ip -n "$namespace" link set dev "$interface" xdp off >/dev/null 2>&1; then
            echo "run-soak.sh: failed to detach XDP from $namespace/$interface" >&2
            return 1
        fi
    else
        echo "run-soak.sh: cannot detach XDP because namespace is missing: $namespace" >&2
        return 1
    fi
    return 0
}

inspect_xdp_residual()
{
    residual=0
    inspect_failed=0
    xdp_lan_residual=0
    xdp_wan_residual=0
    for interface in "$lan_if" "$wan_if"; do
        if details=$(ip -n "$daemon_ns" -details link show dev "$interface" 2>&1); then
            if printf '%s\n' "$details" | grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)'; then
                residual=1
                if [ "$interface" = "$lan_if" ]; then
                    xdp_lan_residual=1
                else
                    xdp_wan_residual=1
                fi
            fi
        else
            echo "run-soak.sh: failed to inspect XDP state on $daemon_ns/$interface" >&2
            printf '%s\n' "$details" >&2
            inspect_failed=1
        fi
    done
    if [ "$inspect_failed" -ne 0 ]; then
        return 2
    fi
    return "$residual"
}

cleanup_xdp()
{
    cleanup_xdp_rc=0
    if ns_exists "$daemon_ns"; then
        :
    else
        namespace_check_rc=$?
        if [ "$namespace_check_rc" -eq 1 ] && [ "$daemon_ns_created" -eq 0 ]; then
            return 0
        fi
        echo "run-soak.sh: failed to inspect XDP state because namespace is unavailable: $daemon_ns" >&2
        if [ "$xdp_residual" = not_checked ]; then
            xdp_residual=inspection_failed
        fi
        add_failure xdp_inspection
        return 1
    fi

    if inspect_xdp_residual; then
        inspect_rc=0
    else
        inspect_rc=$?
    fi

    case "$inspect_rc" in
        0)
            if [ "$xdp_residual" = not_checked ]; then
                xdp_residual=0
            fi
            return 0
            ;;
        1)
            if [ "$xdp_residual" = not_checked ]; then
                xdp_residual=1
            fi
            cleanup_xdp_rc=1
            add_failure xdp_residual
            echo "run-soak.sh: residual XDP program found during cleanup" >&2

            if [ "$xdp_lan_residual" -eq 1 ]; then
                if ! detach_xdp "$daemon_ns" "$lan_if"; then
                    cleanup_xdp_rc=1
                    add_failure xdp_detach
                fi
            fi
            if [ "$xdp_wan_residual" -eq 1 ]; then
                if ! detach_xdp "$daemon_ns" "$wan_if"; then
                    cleanup_xdp_rc=1
                    add_failure xdp_detach
                fi
            fi

            if inspect_xdp_residual; then
                after_inspect_rc=0
            else
                after_inspect_rc=$?
            fi
            case "$after_inspect_rc" in
                0)
                    ;;
                1)
                    cleanup_xdp_rc=1
                    add_failure xdp_residual_after_detach
                    echo "run-soak.sh: XDP program remains after cleanup detach" >&2
                    ;;
                *)
                    cleanup_xdp_rc=1
                    add_failure xdp_inspection_after_detach
                    ;;
            esac
            return "$cleanup_xdp_rc"
            ;;
        *)
            if [ "$xdp_residual" = not_checked ]; then
                xdp_residual=inspection_failed
            fi
            add_failure xdp_inspection
            echo "run-soak.sh: XDP inspection failed during cleanup" >&2
            return 1
            ;;
    esac
}

delete_namespace()
{
    namespace=$1
    if ns_exists "$namespace"; then
        if ! ip netns del "$namespace" >/dev/null 2>&1; then
            echo "run-soak.sh: failed to delete namespace $namespace" >&2
            return 1
        fi
        if ns_exists "$namespace"; then
            echo "run-soak.sh: namespace still exists after deletion: $namespace" >&2
            return 1
        else
            namespace_check_rc=$?
            if [ "$namespace_check_rc" -ne 1 ]; then
                echo "run-soak.sh: failed to verify deletion of namespace $namespace" >&2
                return 1
            fi
        fi
    else
        namespace_check_rc=$?
        if [ "$namespace_check_rc" -gt 1 ]; then
            echo "run-soak.sh: failed to inspect namespace $namespace during cleanup" >&2
            return 1
        fi
    fi
    return 0
}

print_final_record()
{
    requested_rc=$1
    [ "$final_printed" -eq 0 ] || return 0
    final_printed=1

    verdict=pass
    if [ "$requested_rc" -ne 0 ] || [ "$failures" != none ]; then
        verdict=fail
    fi

    echo "measurement_kind=soak backend=$backend duration_sec=$duration_sec sample_count=$sample_count process_deaths=$process_deaths forwarded_total=$forwarded_total forwarded_monotonic=$forwarded_monotonic rss_first_kib=$rss_first_kib rss_last_kib=$rss_last_kib rss_max_kib=$rss_max_kib rss_slope_kib_per_min=$rss_slope_kib_per_min fd_first=$fd_first fd_last=$fd_last fd_max=$fd_max threads_first=$threads_first threads_last=$threads_last threads_max=$threads_max error_counter_total=$error_counter_total shutdown_rc=$shutdown_rc xdp_residual=$xdp_residual verdict=$verdict failures=$failures"
}

cleanup()
{
    rc=$?
    trap - 0 1 2 3 15
    trap '' 1 2 3 15

    cleanup_rc=0
    stop_child "$client_pid" sender_client || cleanup_rc=1
    stop_child "$server_pid" receiver_server || cleanup_rc=1
    stop_child "$daemon_pid" daemon || cleanup_rc=1

    if [ "$backend" = af_xdp ]; then
        cleanup_xdp || cleanup_rc=1
    fi

    for namespace in "$receiver_ns" "$daemon_ns" "$sender_ns"; do
        delete_namespace "$namespace" || cleanup_rc=1
    done

    if [ "$rc" -ne 0 ] || [ "$cleanup_rc" -ne 0 ] || [ "$failures" != none ]; then
        dump_log "$validate_log" validate
        dump_log "$client_log" sender_client
        dump_log "$server_log" receiver_server
        dump_log "$daemon_log" daemon
    fi

    if ! rm -rf "$workdir"; then
        echo "run-soak.sh: failed to remove temporary directory $workdir" >&2
        cleanup_rc=1
    fi

    if [ "$cleanup_rc" -ne 0 ]; then
        add_failure cleanup
        rc=1
    fi
    if [ "$failures" != none ]; then
        rc=1
    fi

    print_final_record "$rc"
    exit "$rc"
}

trap 'add_failure interrupted; exit 130' INT
trap 'add_failure interrupted; exit 143' TERM
trap 'add_failure interrupted; exit 129' HUP
trap 'add_failure interrupted; exit 131' QUIT
trap cleanup EXIT

disable_ipv6_on_interface()
{
    namespace=$1
    interface=$2
    key="net.ipv6.conf.$interface.disable_ipv6"
    if ! ip netns exec "$namespace" sysctl -w "$key=1" >/dev/null; then
        echo "run-soak.sh: failed to disable IPv6 on $namespace/$interface" >&2
        return 1
    fi
    value=$(ip netns exec "$namespace" sysctl -n "$key") || {
        echo "run-soak.sh: failed to read back $key in $namespace" >&2
        return 1
    }
    if [ "$value" != 1 ]; then
        echo "run-soak.sh: $key in $namespace read back '$value', expected 1" >&2
        return 1
    fi
    return 0
}

wait_for_ready_file()
{
    pid=$1
    path=$2
    label=$3
    loops=0
    while [ "$loops" -lt 100 ]; do
        if [ -f "$path" ]; then
            return 0
        fi
        if ! process_running "$pid"; then
            count_process_death "$pid" "$label" "${label}_died_before_ready" || :
            add_failure "${label}_died_before_ready"
            echo "run-soak.sh: $label exited before READY" >&2
            return 1
        fi
        sleep 0.1
        loops=$((loops + 1))
    done
    add_failure "${label}_ready_timeout"
    echo "run-soak.sh: timed out waiting for $label READY" >&2
    return 1
}

get_field()
{
    key=$1
    line=$2
    for token in $line; do
        case "$token" in
            "$key"=*)
                printf '%s\n' "${token#*=}"
                return 0
                ;;
        esac
    done
    return 1
}

require_numeric_field()
{
    key=$1
    line=$2
    value=$(get_field "$key" "$line") || return 1
    case "$value" in
        ''|*[!0123456789]*)
            return 1
            ;;
    esac
    printf '%s\n' "$value"
    return 0
}

collect_error_fields()
{
    line=$1
    : >"$current_errors_path"
    for token in $line; do
        case "$token" in
            dropped=*|tx_rejected=*|reload_rejected=*|reload_restart_required=*|reload_deferred=*|reload_backend_mismatch=*|drop_reason_total=*|drop_reason_*=*)
                key=${token%%=*}
                value=${token#*=}
                case "$value" in
                    ''|*[!0123456789]*)
                        echo "run-soak.sh: error counter $key is not numeric: $value" >&2
                        return 1
                        ;;
                esac
                printf '%s\t%s\n' "$key" "$value" >>"$current_errors_path"
                ;;
        esac
    done
    return 0
}

observability_required_keys='record_type config_generation readiness health reload_requests reload_results reload_applied reload_rejected reload_restart_required reload_unchanged reload_deferred reload_backend_mismatch reload_last_result ticks active_ticks forwarded dropped consumed tx_accepted tx_rejected firewall_processed firewall_denied firewall_processed_per_tick_high_watermark firewall_denied_per_tick_high_watermark nat44_udp_processed nat44_udp_denied nat44_udp_processed_per_tick_high_watermark nat44_udp_denied_per_tick_high_watermark nat44_tcp_processed nat44_tcp_denied nat44_tcp_processed_per_tick_high_watermark nat44_tcp_denied_per_tick_high_watermark queue_high_watermark queue_rx_batch_high_watermark queue_resolution_high_watermark queue_failure_high_watermark queue_generated_arp_high_watermark queue_generated_icmpv4_high_watermark capacity_high_watermark capacity_rx_high_watermark capacity_resolution_timer_high_watermark capacity_failure_dispatch_high_watermark capacity_generated_arp_high_watermark capacity_generated_icmpv4_high_watermark capacity_source backend_mode backend_copy backend_ring_capacity_high_watermark drop_reason_total'

observability_numeric_keys='config_generation reload_requests reload_results reload_applied reload_rejected reload_restart_required reload_unchanged reload_deferred reload_backend_mismatch ticks active_ticks forwarded dropped consumed tx_accepted tx_rejected firewall_processed firewall_denied firewall_processed_per_tick_high_watermark firewall_denied_per_tick_high_watermark nat44_udp_processed nat44_udp_denied nat44_udp_processed_per_tick_high_watermark nat44_udp_denied_per_tick_high_watermark nat44_tcp_processed nat44_tcp_denied nat44_tcp_processed_per_tick_high_watermark nat44_tcp_denied_per_tick_high_watermark queue_high_watermark queue_rx_batch_high_watermark queue_resolution_high_watermark queue_failure_high_watermark queue_generated_arp_high_watermark queue_generated_icmpv4_high_watermark capacity_high_watermark capacity_rx_high_watermark capacity_resolution_timer_high_watermark capacity_failure_dispatch_high_watermark capacity_generated_arp_high_watermark capacity_generated_icmpv4_high_watermark drop_reason_total'

is_required_observability_key()
{
    wanted_key=$1
    for required_key in $observability_required_keys; do
        if [ "$required_key" = "$wanted_key" ]; then
            return 0
        fi
    done
    return 1
}

is_allowed_observability_key()
{
    candidate_key=$1
    if is_required_observability_key "$candidate_key"; then
        return 0
    fi
    case "$candidate_key" in
        drop_reason_*)
            drop_reason_name=${candidate_key#drop_reason_}
            [ -n "$drop_reason_name" ] || return 1
            case "$drop_reason_name" in
                *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
                    return 1
                    ;;
            esac
            return 0
            ;;
    esac
    return 1
}

sample_resources()
{
    pid=$1
    rss=$(awk '/VmRSS:/ { print $2; found=1 } END { if (!found) exit 1 }' "/proc/$pid/status") || return 1
    threads=$(awk '/Threads:/ { print $2; found=1 } END { if (!found) exit 1 }' "/proc/$pid/status") || return 1
    fd_dir="/proc/$pid/fd"
    if [ ! -d "$fd_dir" ] || [ ! -r "$fd_dir" ] || [ ! -x "$fd_dir" ]; then
        echo "run-soak.sh: cannot access file descriptor directory for pid=$pid" >&2
        return 1
    fi

    fd_count=0
    fd_loop_rc=0
    set +f
    for fd_entry in "$fd_dir"/*; do
        if [ "$fd_entry" = "$fd_dir/*" ]; then
            echo "run-soak.sh: file descriptor glob did not expand for pid=$pid" >&2
            fd_loop_rc=1
            break
        fi
        if [ ! -e "$fd_entry" ] && [ ! -L "$fd_entry" ]; then
            echo "run-soak.sh: file descriptor entry disappeared or is inaccessible: $fd_entry" >&2
            fd_loop_rc=1
            break
        fi
        fd_count=$((fd_count + 1))
    done
    set -f
    if [ "$fd_loop_rc" -ne 0 ]; then
        return 1
    fi
    case "$fd_count" in
        ''|*[!0123456789]*)
            echo "run-soak.sh: file descriptor count is not numeric: $fd_count" >&2
            return 1
            ;;
    esac
    printf '%s %s %s\n' "$rss" "$fd_count" "$threads"
}

validate_observability_line()
{
    line=$1

    [ -n "$line" ] || {
        echo "run-soak.sh: observability response was empty" >&2
        return 1
    }

    seen_keys=
    for token in $line; do
        case "$token" in
            *=*)
                ;;
            *)
                echo "run-soak.sh: observability token is not key=value: $token" >&2
                return 1
                ;;
        esac

        key=${token%%=*}
        value=${token#*=}
        if [ -z "$key" ] || [ "$key" = "$token" ]; then
            echo "run-soak.sh: observability token has an empty key: $token" >&2
            return 1
        fi
        case "$value" in
            *=*)
                echo "run-soak.sh: observability token has more than one '=': $token" >&2
                return 1
                ;;
        esac
        case "$key" in
            *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
                echo "run-soak.sh: observability key is invalid: $key" >&2
                return 1
                ;;
        esac
        case " $seen_keys " in
            *" $key "*)
                echo "run-soak.sh: duplicate observability key: $key" >&2
                return 1
                ;;
        esac
        if ! is_allowed_observability_key "$key"; then
            echo "run-soak.sh: unknown observability key: $key" >&2
            return 1
        fi
        case "$key" in
            drop_reason_*)
                case "$value" in
                    ''|*[!0123456789]*)
                        echo "run-soak.sh: drop reason counter $key is not numeric: $value" >&2
                        return 1
                        ;;
                esac
                ;;
        esac
        seen_keys="$seen_keys $key"
    done

    for key in $observability_required_keys; do
        if ! get_field "$key" "$line" >/dev/null; then
            echo "run-soak.sh: required observability key is missing: $key" >&2
            return 1
        fi
    done

    record_type=$(get_field record_type "$line") || return 1
    if [ "$record_type" != observability ]; then
        echo "run-soak.sh: record_type=$record_type, expected observability" >&2
        return 1
    fi

    readiness=$(get_field readiness "$line") || return 1
    health=$(get_field health "$line") || return 1
    backend_mode=$(get_field backend_mode "$line") || return 1
    if [ "$readiness" != ready ]; then
        echo "run-soak.sh: readiness=$readiness, expected ready" >&2
        return 1
    fi
    if [ "$health" != healthy ]; then
        echo "run-soak.sh: health=$health, expected healthy" >&2
        return 1
    fi
    if [ "$backend_mode" != "$expected_backend_mode" ]; then
        echo "run-soak.sh: backend_mode=$backend_mode, expected $expected_backend_mode" >&2
        return 1
    fi

    for key in $observability_numeric_keys
    do
        require_numeric_field "$key" "$line" >/dev/null || {
            echo "run-soak.sh: required numeric field missing or invalid: $key" >&2
            return 1
        }
    done

    backend_copy=$(get_field backend_copy "$line") || return 1
    case "$backend_copy" in
        true|false)
            ;;
        *)
            echo "run-soak.sh: backend_copy is not boolean: $backend_copy" >&2
            return 1
            ;;
    esac
    capacity_source=$(get_field capacity_source "$line") || return 1
    if [ "$capacity_source" != tick_budget ]; then
        echo "run-soak.sh: capacity_source=$capacity_source, expected tick_budget" >&2
        return 1
    fi
    backend_ring_capacity=$(get_field backend_ring_capacity_high_watermark "$line") || return 1
    if [ "$backend_ring_capacity" != unavailable ]; then
        echo "run-soak.sh: unexpected backend ring capacity value: $backend_ring_capacity" >&2
        return 1
    fi
    reload_last_result=$(get_field reload_last_result "$line") || return 1
    case "$reload_last_result" in
        none|applied|rejected|restart_required|unchanged|deferred|backend_mismatch)
            ;;
        *)
            echo "run-soak.sh: invalid reload_last_result: $reload_last_result" >&2
            return 1
            ;;
    esac

    collect_error_fields "$line" || return 1
    return 0
}

calculate_error_counter_total()
{
    # error_counter_total is the sum of independent top-level counters only.
    # dropped is the total represented by drop_reason_total/drop_reason_*, so
    # those classification counters must not be added again.
    awk '
        $1 == "dropped" || \
        $1 == "tx_rejected" || \
        $1 == "reload_rejected" || \
        $1 == "reload_restart_required" || \
        $1 == "reload_deferred" || \
        $1 == "reload_backend_mismatch" {
            total += $2
        }
        END { print total + 0 }
    ' "$1"
}

check_error_increases()
{
    current_total=$(calculate_error_counter_total "$current_errors_path") || return 1
    error_counter_total=$current_total

    if [ "$sample_count" -eq 0 ]; then
        cp "$current_errors_path" "$previous_errors_path"
        return 0
    fi

    comparison=$(awk '
        NR == FNR {
            previous[$1] = $2
            next
        }
        {
            current[$1] = $2
            if (!($1 in previous)) {
                invalid = 1
                printf "run-soak.sh: error counter added: %s\n", $1 > "/dev/stderr"
            } else if ($2 < previous[$1]) {
                invalid = 1
                printf "run-soak.sh: error counter decreased: %s %s -> %s\n", $1, previous[$1], $2 > "/dev/stderr"
            } else if ($2 > previous[$1]) {
                increased = 1
                printf "run-soak.sh: error counter increased: %s %s -> %s\n", $1, previous[$1], $2 > "/dev/stderr"
            }
        }
        END {
            for (key in previous) {
                if (!(key in current)) {
                    invalid = 1
                    printf "run-soak.sh: error counter missing: %s\n", key > "/dev/stderr"
                }
            }
            print invalid + 0, increased + 0
        }
    ' "$previous_errors_path" "$current_errors_path") || return 1

    set -- $comparison
    invalid_counters=$1
    increased_counters=$2

    if [ "$invalid_counters" -ne 0 ]; then
        add_failure error_counter_invalid
        echo "run-soak.sh: error counter set or value changed invalidly" >&2
        return 1
    fi
    if [ "$increased_counters" -ne 0 ]; then
        add_failure error_counter_increase
        echo "run-soak.sh: error counters increased" >&2
        return 1
    fi
    cp "$current_errors_path" "$previous_errors_path"
    return 0
}

compute_summary()
{
    if [ ! -s "$samples_path" ]; then
        return 0
    fi

    summary=$(awk '
        NR == 1 {
            prev_forwarded = $3
            prev_ticks = $4
            monotonic = 1
        }
        {
            n = NR
            timestamp[n] = $2
            forwarded[n] = $3
            ticks[n] = $4
            rss[n] = $5
            fd[n] = $6
            threads[n] = $7
            if (NR > 1 && ($3 <= prev_forwarded || $4 <= prev_ticks)) {
                monotonic = 0
            }
            prev_forwarded = $3
            prev_ticks = $4
        }
        END {
            if (n == 0) {
                exit
            }
            post_first = 4
            post_count = n - 3

            # First/last/max describe every valid sample.  Only the slope
            # below is calculated from samples after the first three warmups.
            rss_first = rss[1]
            rss_last = rss[n]
            rss_max = rss[1]
            fd_first = fd[1]
            fd_last = fd[n]
            fd_max = fd[1]
            threads_first = threads[1]
            threads_last = threads[n]
            threads_max = threads[1]
            for (i = 1; i <= n; i++) {
                if (rss[i] > rss_max) rss_max = rss[i]
                if (fd[i] > fd_max) fd_max = fd[i]
                if (threads[i] > threads_max) threads_max = threads[i]
            }

            slope = "missing"
            slope_status = "too_few_post_warmup_samples"
            if (post_count >= 2) {
                sum_x = 0
                sum_y = 0
                sum_xx = 0
                sum_xy = 0
                base = timestamp[post_first]
                for (i = post_first; i <= n; i++) {
                    x = (timestamp[i] - base) / 60.0
                    y = rss[i]
                    sum_x += x
                    sum_y += y
                    sum_xx += x * x
                    sum_xy += x * y
                }
                denominator = post_count * sum_xx - sum_x * sum_x
                if (denominator != 0) {
                    slope = sprintf("%.3f", (post_count * sum_xy - sum_x * sum_y) / denominator)
                    slope_status = "ok"
                } else {
                    slope_status = "timestamp_resolution"
                }
            }

            print n, forwarded[n], monotonic ? "true" : "false", rss_first, rss_last, rss_max, slope, slope_status, fd_first, fd_last, fd_max, threads_first, threads_last, threads_max
        }
    ' "$samples_path")

    set -- $summary
    sample_count=$1
    forwarded_total=$2
    forwarded_monotonic=$3
    rss_first_kib=$4
    rss_last_kib=$5
    rss_max_kib=$6
    rss_slope_kib_per_min=$7
    rss_slope_status=$8
    fd_first=$9
    fd_last=${10}
    fd_max=${11}
    threads_first=${12}
    threads_last=${13}
    threads_max=${14}
}

check_post_warmup_growth()
{
    post_warmup_count=$(awk 'NR > 3 { count++ } END { print count + 0 }' "$samples_path")
    if [ "$post_warmup_count" -lt 2 ]; then
        add_failure too_few_post_warmup_samples
        echo "run-soak.sh: need at least 2 post-warmup samples, got $post_warmup_count" >&2
        return 1
    fi

    if awk 'BEGIN { growth = 0; seen = 0 } NR > 3 { current = $6 + 0; if (seen && current > previous) growth = 1; previous = current; seen = 1 } END { exit !(seen && growth != 0) }' "$samples_path"; then
        add_failure fd_continued_growth
        echo "run-soak.sh: fd count continued growing after warmup" >&2
        return 1
    fi
    if awk 'BEGIN { growth = 0; seen = 0 } NR > 3 { current = $7 + 0; if (seen && current > previous) growth = 1; previous = current; seen = 1 } END { exit !(seen && growth != 0) }' "$samples_path"; then
        add_failure threads_continued_growth
        echo "run-soak.sh: thread count continued growing after warmup" >&2
        return 1
    fi

    case "$rss_slope_kib_per_min" in
        missing)
            if [ "$rss_slope_status" = too_few_post_warmup_samples ]; then
                add_failure too_few_post_warmup_samples
                echo "run-soak.sh: RSS slope unavailable because there are too few post-warmup samples" >&2
            else
                add_failure rss_slope_timestamp_resolution
                echo "run-soak.sh: RSS slope unavailable because post-warmup timestamps have no interval" >&2
            fi
            return 1
            ;;
        *)
            # 1024 KiB/min is 256 sustained 4 KiB pages per minute, which is
            # enough growth to be actionable in this soak fixture.
            if awk -v slope="$rss_slope_kib_per_min" 'BEGIN { exit !(slope > 1024.0) }'; then
                add_failure rss_slope_high
                echo "run-soak.sh: RSS slope ${rss_slope_kib_per_min} KiB/min exceeds 1024 KiB/min" >&2
                return 1
            fi
            ;;
    esac

    return 0
}

for namespace in "$sender_ns" "$daemon_ns" "$receiver_ns"; do
    if ns_exists "$namespace"; then
        add_failure namespace_collision
        echo "run-soak.sh: generated namespace already exists: $namespace" >&2
        exit 1
    else
        namespace_check_rc=$?
        if [ "$namespace_check_rc" -gt 1 ]; then
            add_failure namespace_check
            echo "run-soak.sh: failed to inspect namespace collisions" >&2
            exit 1
        fi
    fi
done

for interface in "$sender_if" "$lan_if" "$wan_if" "$receiver_if"; do
    case "$interface" in
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*|????????????????*)
            add_failure interface_name_invalid
            echo "run-soak.sh: generated interface name is invalid or longer than 15 bytes: $interface" >&2
            exit 1
            ;;
    esac
    if ip link show dev "$interface" >/dev/null 2>&1; then
        add_failure interface_collision
        echo "run-soak.sh: generated interface collides with existing link: $interface" >&2
        exit 1
    fi
done

cp "$repo_root/crates/control/tests/full-service.toml" "$config_path"
sed -i \
    -e "s/device = \"eth1\"/device = \"$wan_if\"/" \
    -e "s/device = \"eth0\"/device = \"$lan_if\"/" \
    "$config_path"

if [ "$backend" = af_xdp ]; then
    cat >>"$config_path" <<EOF

[backend]
kind = "af-xdp"
xskmap-max-entries = 1
bind-flags = 10
attach-mode = "skb"

[backend.umem]
frame-count = 4
frame-size = 2048
headroom = 0
rx-frames = 1
generated-frames = 3
raw-flags = 0

[backend.rings]
fill = 2
rx = 2
tx = 2
completion = 2

[[backend.resources]]
interface = "wan"
queue-id = 0

[[backend.resources]]
interface = "lan"
queue-id = 0
EOF
fi

ip netns add "$sender_ns"
ip netns add "$daemon_ns"
daemon_ns_created=1
ip netns add "$receiver_ns"

ip link add "$sender_if" type veth peer name "$lan_if"
ip link set dev "$sender_if" netns "$sender_ns"
ip link set dev "$lan_if" netns "$daemon_ns"
ip link add "$wan_if" type veth peer name "$receiver_if"
ip link set dev "$wan_if" netns "$daemon_ns"
ip link set dev "$receiver_if" netns "$receiver_ns"

disable_ipv6_on_interface "$sender_ns" "$sender_if" || {
    add_failure ipv6_disable
    exit 1
}
disable_ipv6_on_interface "$daemon_ns" "$lan_if" || {
    add_failure ipv6_disable
    exit 1
}
disable_ipv6_on_interface "$daemon_ns" "$wan_if" || {
    add_failure ipv6_disable
    exit 1
}
disable_ipv6_on_interface "$receiver_ns" "$receiver_if" || {
    add_failure ipv6_disable
    exit 1
}

ip -n "$sender_ns" link set dev lo up
ip -n "$daemon_ns" link set dev lo up
ip -n "$receiver_ns" link set dev lo up

ip -n "$sender_ns" link set dev "$sender_if" address "$sender_mac"
ip -n "$daemon_ns" link set dev "$lan_if" address "$lan_mac"
ip -n "$daemon_ns" link set dev "$wan_if" address "$wan_mac"
ip -n "$receiver_ns" link set dev "$receiver_if" address "$receiver_mac"

ip -n "$sender_ns" addr add 192.0.2.20/24 dev "$sender_if"
ip -n "$daemon_ns" addr add 192.0.2.1/24 dev "$lan_if"
ip -n "$daemon_ns" addr add 198.51.100.10/24 dev "$wan_if"
ip -n "$receiver_ns" addr add 198.51.100.1/24 dev "$receiver_if"

ip -n "$sender_ns" link set dev "$sender_if" up
ip -n "$daemon_ns" link set dev "$lan_if" up
ip -n "$daemon_ns" link set dev "$wan_if" up
ip -n "$receiver_ns" link set dev "$receiver_if" up

ip netns exec "$sender_ns" ethtool -K "$sender_if" tx-checksumming off
ip netns exec "$daemon_ns" ethtool -K "$lan_if" tx-checksumming off
ip netns exec "$daemon_ns" ethtool -K "$wan_if" tx-checksumming off
ip netns exec "$receiver_ns" ethtool -K "$receiver_if" tx-checksumming off

ip -n "$sender_ns" route add default via 192.0.2.1 dev "$sender_if"
ip -n "$receiver_ns" route add default via 198.51.100.10 dev "$receiver_if"
ip -n "$sender_ns" neigh replace 192.0.2.1 lladdr "$lan_mac" nud permanent dev "$sender_if"
ip -n "$daemon_ns" neigh replace 192.0.2.20 lladdr "$sender_mac" nud permanent dev "$lan_if"
ip -n "$daemon_ns" neigh replace 198.51.100.1 lladdr "$receiver_mac" nud permanent dev "$wan_if"
ip -n "$receiver_ns" neigh replace 198.51.100.10 lladdr "$wan_mac" nud permanent dev "$receiver_if"

if [ "$backend" = af_packet ]; then
    # ruster owns the NAT wire flow in userspace.  Do not let the daemon
    # namespace kernel own the public address: an inbound SYN-ACK to that
    # local address would otherwise reach TCP and produce an RST for the
    # userspace flow.  The receiver's permanent neighbor and ruster's
    # AF_PACKET TX do not require this address to be assigned in the daemon
    # namespace.
    if ! ip -n "$daemon_ns" addr del 198.51.100.10/24 dev "$wan_if"; then
        add_failure daemon_public_address
        echo "run-soak.sh: failed to remove NAT public address from $daemon_ns/$wan_if" >&2
        exit 1
    fi
    if daemon_wan_addresses=$(ip -n "$daemon_ns" -4 addr show dev "$wan_if"); then
        :
    else
        add_failure daemon_public_address_check
        echo "run-soak.sh: failed to inspect addresses on $daemon_ns/$wan_if after removal" >&2
        exit 1
    fi
    if printf '%s\n' "$daemon_wan_addresses" | awk '$1 == "inet" && $2 ~ /^198[.]51[.]100[.]10\// { found=1 } END { exit(found ? 0 : 1) }'; then
        add_failure daemon_public_address
        echo "run-soak.sh: NAT public address is still assigned to $daemon_ns/$wan_if" >&2
        exit 1
    else
        daemon_public_address_check_rc=$?
        if [ "$daemon_public_address_check_rc" -ne 1 ]; then
            add_failure daemon_public_address_check
            echo "run-soak.sh: failed to verify NAT public address removal from $daemon_ns/$wan_if" >&2
            exit 1
        fi
    fi
fi

if ! ip netns exec "$daemon_ns" "$binary" validate "$config_path" >"$validate_log" 2>&1; then
    add_failure validate
    echo "run-soak.sh: ruster validate rejected the soak configuration" >&2
    exit 1
fi

ip netns exec "$daemon_ns" env \
    RUSTER_CONTROL_SOCKET="$control_socket" \
    RUSTER_OBSERVABILITY_INTERVAL_SECS=1 \
    "$binary" run "$config_path" >"$daemon_log" 2>&1 &
daemon_pid=$!

daemon_ready=0
ready_loops=0
while [ "$ready_loops" -lt 300 ]; do
    count_process_death "$daemon_pid" daemon daemon_died_before_ready || exit 1
    if ip netns exec "$daemon_ns" env RUSTER_CONTROL_SOCKET="$control_socket" "$binary" status >/dev/null 2>&1; then
        daemon_ready=1
        break
    fi
    sleep 0.1
    ready_loops=$((ready_loops + 1))
done
if [ "$daemon_ready" -ne 1 ]; then
    add_failure daemon_ready_timeout
    echo "run-soak.sh: daemon did not accept status requests before timeout" >&2
    exit 1
fi

ip netns exec "$receiver_ns" python3 -u -c "
import socket
import sys
from pathlib import Path

ready_path = Path('$server_ready')
payload_length = len(b'ruster-soak')
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    listener.bind(('198.51.100.1', 443))
    listener.listen(128)
    ready_path.write_text('READY\n')
    print('READY', flush=True)
    while True:
        connection, peer = listener.accept()
        with connection:
            while True:
                data = b''
                while len(data) < payload_length:
                    chunk = connection.recv(payload_length - len(data))
                    if not chunk:
                        if data:
                            raise RuntimeError('connection closed mid-payload from %r' % (peer,))
                        break
                    data += chunk
                if not data:
                    break
                if len(data) != payload_length:
                    raise RuntimeError('short payload from %r' % (peer,))
                connection.sendall(data)
except KeyboardInterrupt:
    raise
except BaseException as error:
    print('server failure: %r' % (error,), file=sys.stderr, flush=True)
    sys.exit(1)
" >"$server_log" 2>&1 &
server_pid=$!
wait_for_ready_file "$server_pid" "$server_ready" server || exit 1

ip netns exec "$sender_ns" python3 -u -c "
import socket
import sys
from pathlib import Path

ready_path = Path('$client_ready')
payload = b'ruster-soak'
connection = None
try:
    connection = socket.create_connection(('198.51.100.1', 443), timeout=2.0)
    connection.settimeout(2.0)
    ready_path.write_text('READY\n')
    print('READY', flush=True)
    while True:
        connection.sendall(payload)
        data = b''
        while len(data) < len(payload):
            chunk = connection.recv(len(payload) - len(data))
            if not chunk:
                raise RuntimeError('server closed before echo completed')
            data += chunk
        if data != payload:
            raise RuntimeError('unexpected echo: %r' % (data,))
except KeyboardInterrupt:
    raise
except BaseException as error:
    print('client failure: %r' % (error,), file=sys.stderr, flush=True)
    sys.exit(1)
finally:
    if connection is not None:
        connection.close()
" >"$client_log" 2>&1 &
client_pid=$!
wait_for_ready_file "$client_pid" "$client_ready" client || exit 1

previous_forwarded=
previous_ticks=
elapsed_sec=0

while [ "$elapsed_sec" -lt "$duration_sec" ]; do
    count_process_death "$daemon_pid" daemon daemon_died || break
    count_process_death "$server_pid" receiver_server server_died || break
    count_process_death "$client_pid" sender_client client_died || break

    status_output=$(ip netns exec "$daemon_ns" env RUSTER_CONTROL_SOCKET="$control_socket" "$binary" status 2>&1) || {
        add_failure status_query
        echo "run-soak.sh: status query failed: $status_output" >&2
        break
    }
    line_count=$(printf '%s\n' "$status_output" | awk 'END { print NR }')
    if [ "$line_count" -ne 1 ]; then
        add_failure observability_line_count
        echo "run-soak.sh: expected exactly one status line, got $line_count" >&2
        break
    fi

    if ! validate_observability_line "$status_output"; then
        add_failure observability_invalid
        break
    fi
    if ! check_error_increases; then
        break
    fi

    forwarded=$(require_numeric_field forwarded "$status_output") || {
        add_failure forwarded_invalid
        break
    }
    ticks=$(require_numeric_field ticks "$status_output") || {
        add_failure ticks_invalid
        break
    }

    if [ -n "$previous_forwarded" ] && [ "$forwarded" -le "$previous_forwarded" ]; then
        add_failure forwarded_not_increasing
        echo "run-soak.sh: forwarded did not increase: previous=$previous_forwarded current=$forwarded" >&2
        break
    fi
    if [ -n "$previous_ticks" ] && [ "$ticks" -le "$previous_ticks" ]; then
        add_failure ticks_not_increasing
        echo "run-soak.sh: ticks did not increase: previous=$previous_ticks current=$ticks" >&2
        break
    fi
    previous_forwarded=$forwarded
    previous_ticks=$ticks

    resource_sample=$(sample_resources "$daemon_pid") || {
        add_failure resource_sample
        break
    }
    set -- $resource_sample
    if [ "$#" -ne 3 ]; then
        add_failure resource_sample
        echo "run-soak.sh: resource sample did not contain exactly three fields" >&2
        break
    fi
    rss_kib=$1
    fd_count=$2
    threads=$3

    sample_count=$((sample_count + 1))
    sample_time=$((sample_count * sample_interval_sec))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$sample_count" "$sample_time" "$forwarded" "$ticks" "$rss_kib" "$fd_count" "$threads" \
        >>"$samples_path"
    echo "sample_index=$sample_count timestamp_sec=$sample_time forwarded=$forwarded ticks=$ticks rss_kib=$rss_kib fd_count=$fd_count threads=$threads" >&2

    sleep "$sample_interval_sec"
    elapsed_sec=$((elapsed_sec + sample_interval_sec))
done

# Check all traffic processes at the duration boundary, before intentional
# shutdown can hide a death between the last sample and cleanup.
check_traffic_processes || :

compute_summary

if [ "$sample_count" -lt 5 ]; then
    add_failure too_few_samples
    echo "run-soak.sh: need at least 5 valid samples for 3 warmup and 2 post-warmup samples, got $sample_count" >&2
fi
if [ "$forwarded_monotonic" != true ]; then
    add_failure forwarded_or_ticks_not_monotonic
fi
check_post_warmup_growth || :

stop_child "$client_pid" sender_client || add_failure client_shutdown
client_pid=
stop_child "$server_pid" receiver_server || add_failure server_shutdown
server_pid=

if [ -n "$daemon_pid" ]; then
    if process_running "$daemon_pid"; then
        if kill -TERM "$daemon_pid" 2>/dev/null; then
            if wait "$daemon_pid"; then
                shutdown_rc=0
            else
                shutdown_rc=$?
            fi
            mark_process_reaped daemon
            if [ "$shutdown_rc" -ne 0 ]; then
                add_failure daemon_shutdown
                echo "run-soak.sh: daemon exited with status $shutdown_rc after SIGTERM" >&2
            fi
        else
            shutdown_rc=signal_failed
            add_failure daemon_signal
            echo "run-soak.sh: failed to send SIGTERM to daemon" >&2
            if process_running "$daemon_pid"; then
                stop_child "$daemon_pid" daemon || add_failure daemon_cleanup
            else
                add_failure daemon_early_death_shutdown
                if ! process_was_reaped daemon; then
                    process_deaths=$((process_deaths + 1))
                    wait "$daemon_pid" >/dev/null 2>&1 || :
                    mark_process_reaped daemon
                fi
            fi
        fi
    else
        add_failure daemon_early_death_shutdown
        shutdown_rc=early_death
        if ! process_was_reaped daemon; then
            process_deaths=$((process_deaths + 1))
            wait "$daemon_pid" >/dev/null 2>&1 || :
            mark_process_reaped daemon
        fi
    fi
    daemon_pid=
fi

if [ "$backend" = af_xdp ]; then
    if inspect_xdp_residual; then
        xdp_residual=0
    else
        inspect_rc=$?
        if [ "$inspect_rc" -eq 1 ]; then
            xdp_residual=1
            add_failure xdp_residual
            echo "run-soak.sh: XDP program remains attached after daemon shutdown" >&2
        else
            xdp_residual=inspection_failed
            add_failure xdp_inspection
        fi
    fi
else
    xdp_residual=0
fi

if [ "$failures" != none ]; then
    exit 1
fi

exit 0
