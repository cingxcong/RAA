"""Perfetto Dynamic System Tracing & Binder IPC Storm Analyzer.

Captures system traces via Perfetto/ftrace on Android emulators and devices,
correlating kernel thread scheduling, Binder IPC transactions, and CPU spin-loops
to detect anti-analysis evasion, thread starvation, and lock contention ANR deadlocks.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any

DEFAULT_PERFETTO_CONFIG = """buffers: {
    size_kb: 16384
    fill_policy: RING_BUFFER
}
data_sources: {
    config {
        name: "linux.ftrace"
        ftrace_config {
            ftrace_events: "sched/sched_switch"
            ftrace_events: "sched/sched_wakeup"
            ftrace_events: "binder/binder_transaction"
            ftrace_events: "binder/binder_transaction_received"
            ftrace_events: "power/cpu_frequency"
        }
    }
}
duration_ms: 5000
"""


def generate_perfetto_config(
    duration_ms: int = 5000,
    buffer_kb: int = 16384,
    enable_binder: bool = True,
    enable_scheduling: bool = True,
) -> str:
    """Generate a valid Perfetto text-format trace configuration file (.pftxt)."""
    events: list[str] = []
    if enable_scheduling:
        events.extend(['"sched/sched_switch"', '"sched/sched_wakeup"', '"power/cpu_frequency"'])
    if enable_binder:
        events.extend(['"binder/binder_transaction"', '"binder/binder_transaction_received"'])

    event_lines = "\n".join(f"            ftrace_events: {e}" for e in events)

    return f"""buffers: {{
    size_kb: {buffer_kb}
    fill_policy: RING_BUFFER
}}
data_sources: {{
    config {{
        name: "linux.ftrace"
        ftrace_config {{
{event_lines}
        }}
    }}
}}
duration_ms: {duration_ms}
"""


def record_perfetto_trace(
    package_name: str,
    duration_ms: int = 5000,
    device_id: str | None = None,
    output_trace_path: str = "/data/misc/perfetto-traces/trace.perfetto-trace",
) -> dict[str, Any]:
    """Generate ADB command and session metadata to execute Perfetto tracing on target device."""
    dev_flag = f"-s {device_id} " if device_id else ""
    config_pftxt = generate_perfetto_config(duration_ms=duration_ms)

    # Shell command piped into Android perfetto binary
    adb_record_cmd = (
        f'adb {dev_flag}shell \'echo "{config_pftxt.replace(chr(10), " ")}" | '
        f"perfetto -c - -o {output_trace_path}'"
    )
    adb_pull_cmd = f"adb {dev_flag}pull {output_trace_path} ./trace.perfetto-trace"

    return {
        "package_name": package_name,
        "duration_ms": duration_ms,
        "output_path_device": output_trace_path,
        "adb_record_command": adb_record_cmd,
        "adb_pull_command": adb_pull_cmd,
        "config_pftxt": config_pftxt,
        "status": "trace_configured",
    }


def analyze_perfetto_events(
    events_log: str | list[dict[str, Any]],
    target_package: str = "com.example.app",
) -> dict[str, Any]:
    """Analyze Perfetto trace log records and detect Binder storms, spin loops, and ANR risks."""
    binder_transactions = 0
    cpu_active_slices = 0
    ui_thread_blocked_ms = 0.0

    detected_anomalies: list[dict[str, Any]] = []

    if isinstance(events_log, str):
        # Parse text formatted ftrace or perfetto-cli export lines
        for line in events_log.splitlines():
            line_str = line.strip()
            if "binder_transaction" in line_str:
                binder_transactions += 1
            if "sched_switch" in line_str and target_package in line_str:
                cpu_active_slices += 1
            if "blocked" in line_str.lower() or "d-state" in line_str.lower():
                # Extract potential blocked milliseconds
                dur_match = re.search(r"(\d+(\.\d+)?)ms", line_str)
                if dur_match:
                    with contextlib.suppress(Exception):
                        ui_thread_blocked_ms += float(dur_match.group(1))
    elif isinstance(events_log, list):
        for ev in events_log:
            ev_name = str(ev.get("name", ""))
            if "binder" in ev_name.lower():
                binder_transactions += 1
            if "sched" in ev_name.lower():
                cpu_active_slices += 1
            ui_thread_blocked_ms += float(ev.get("dur_ms", 0.0))

    # 1. Binder Storm Detection
    is_binder_storm = binder_transactions > 50
    if is_binder_storm:
        detected_anomalies.append(
            {
                "type": "BINDER_IPC_STORM",
                "severity": "HIGH",
                "count": binder_transactions,
                "description": (
                    f"Excessive Binder IPC transactions ({binder_transactions} events observed) "
                    "indicating rapid cross-process messaging or IPC flooding evasion."
                ),
            }
        )

    # 2. Anti-Analysis Spin Loop Detection
    is_spin_loop = cpu_active_slices > 100 and ui_thread_blocked_ms < 50
    if is_spin_loop:
        detected_anomalies.append(
            {
                "type": "ANTI_ANALYSIS_SPIN_LOOP",
                "severity": "HIGH",
                "slices": cpu_active_slices,
                "description": (
                    "High CPU slice frequency without I/O wait detected, characteristic "
                    "of anti-emulator spin-loops designed to exhaust analysis timeouts."
                ),
            }
        )

    # 3. Lock Contention & ANR Risk Detection
    is_anr_risk = ui_thread_blocked_ms >= 5000.0 or (
        "anr" in str(events_log).lower() and ui_thread_blocked_ms >= 1000.0
    )
    if is_anr_risk:
        detected_anomalies.append(
            {
                "type": "LOCK_CONTENTION_ANR",
                "severity": "CRITICAL",
                "blocked_ms": ui_thread_blocked_ms,
                "description": (
                    f"Main UI thread blocked for {ui_thread_blocked_ms:.1f}ms exceeding "
                    "the 5000ms Android ANR (Application Not Responding) threshold."
                ),
            }
        )

    return {
        "target_package": target_package,
        "binder_transactions": binder_transactions,
        "cpu_active_slices": cpu_active_slices,
        "ui_thread_blocked_ms": ui_thread_blocked_ms,
        "anomaly_count": len(detected_anomalies),
        "anomalies": detected_anomalies,
        "has_binder_storm": is_binder_storm,
        "has_spin_loop": is_spin_loop,
        "has_anr_risk": is_anr_risk,
        "perfetto_sql_summary": (
            f"Trace Analysis for {target_package}: {binder_transactions} Binder calls, "
            f"{cpu_active_slices} CPU slices, {len(detected_anomalies)} anomalies."
        ),
    }
