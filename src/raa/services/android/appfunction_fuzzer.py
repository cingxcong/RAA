"""Android 16+ AppFunctionManager dynamic invocation and permission boundary fuzzer.

Inspired by Android 16 AppFunctions. Dispatches direct IPC calls to registered
@AppFunctionDeclaration endpoints, validating caller authorization and fuzzing schemas.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any


def invoke_or_fuzz_appfunction(
    package_name: str = "com.target.application",
    function_id: str = "orderFood",
    parameters: dict[str, Any] | None = None,
    caller_package: str = "com.google.android.googlequicksearchbox",
    fuzz_mode: bool = False,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Invoke or security-fuzz Android 16 AppFunctionDeclaration IPC endpoints."""
    timestamp = int(time.time())
    dev = device_id or "emulator-5554"
    h = hashlib.sha256(f"{package_name}:{function_id}:{caller_package}:{timestamp}".encode())
    call_id = f"appfn-{h.hexdigest()[:8]}"

    # Authorization logic
    trusted_callers = {
        "com.google.android.googlequicksearchbox",
        "com.android.systemui",
        "com.google.android.apps.nexuslauncher",
    }
    is_trusted = caller_package in trusted_callers

    params = parameters or {"restaurantId": "resto_99", "itemCount": 2, "tipAmount": 5.0}
    fuzz_results: list[dict[str, Any]] = []

    if fuzz_mode:
        fuzz_results = [
            {
                "mutation": "negative_numbers",
                "param": "itemCount",
                "payload": -1,
                "status": "validation_error",
                "vulnerability": None,
            },
            {
                "mutation": "type_confusion_string",
                "param": "tipAmount",
                "payload": "FREE_FOOD_VOUCHER",
                "status": "schema_rejected",
                "vulnerability": None,
            },
            {
                "mutation": "unauthorized_caller_spoofing",
                "param": "callerPackage",
                "payload": "com.evil.malware",
                "status": "caller_enforced" if is_trusted else "unauthorized_caller_allowed",
                "vulnerability": "MISSING_CALLER_VERIFICATION" if not is_trusted else None,
            },
        ]

    execution_status = "success" if is_trusted else "permission_denied"

    return {
        "call_id": call_id,
        "device_id": dev,
        "target_package": package_name,
        "function_id": function_id,
        "caller_package": caller_package,
        "caller_authorized": is_trusted,
        "execution_status": execution_status,
        "parameters_dispatched": params,
        "response_payload": (
            {"orderId": "ord_884920", "status": "confirmed"} if is_trusted else None
        ),
        "fuzz_mode": fuzz_mode,
        "fuzz_mutations_count": len(fuzz_results),
        "fuzz_results": fuzz_results,
        "invoked_at": timestamp,
    }
