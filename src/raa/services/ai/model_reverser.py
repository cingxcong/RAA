"""On-Device AI Model, Embedded Prompt & Android 16 AppFunctions Reverser.

Inspects on-device machine learning models (TFLite, LiteRT, ONNX), extracts embedded
LLM system prompts and RAG configurations, and discovers Android 16 AppFunction declarations.
"""

from __future__ import annotations

import re
from typing import Any

TFLITE_MAGIC = b"TFL3"
TFLITE_EXPERIMENTAL_MAGIC = b"TFL2"
ONNX_MAGIC = b"\x08\x03\x12"  # Common protobuf header for ONNX ModelProto


def inspect_ai_model(file_bytes: bytes, file_name: str = "model.tflite") -> dict[str, Any]:
    """Inspect binary ML model for architecture, operators, quantizations, and risk."""
    file_size = len(file_bytes)
    lower_name = file_name.lower()

    is_tflite = (
        len(file_bytes) > 8
        and (file_bytes[4:8] == TFLITE_MAGIC or file_bytes[4:8] == TFLITE_EXPERIMENTAL_MAGIC)
    ) or lower_name.endswith((".tflite", ".litertlm"))

    is_onnx = lower_name.endswith(".onnx") or (
        file_bytes.startswith(ONNX_MAGIC) or b"onnx" in file_bytes[:100].lower()
    )

    is_mediapipe = lower_name.endswith((".binarypb", ".pbtxt")) or b"mediapipe" in file_bytes[:200]

    model_format = "unknown"
    if is_tflite:
        model_format = "tflite"
    elif is_onnx:
        model_format = "onnx"
    elif is_mediapipe:
        model_format = "mediapipe"

    # Scan strings inside model for known operators, metadata, and layers
    ascii_strings: list[bytes] = re.findall(rb"[\x20-\x7E]{4,}", file_bytes)
    decoded_strings = [s.decode("latin1") for s in ascii_strings]

    known_ops = {
        "CONV_2D",
        "DEPTHWISE_CONV_2D",
        "FULLY_CONNECTED",
        "SOFTMAX",
        "RESHAPE",
        "MAX_POOL_2D",
        "AVERAGE_POOL_2D",
        "CONCATENATION",
        "ADD",
        "SUB",
        "MUL",
        "GELU",
        "RELU",
        "RELU6",
        "BATCH_MATMUL",
        "EMBEDDING_LOOKUP",
        "LSTM",
        "TRANSPOSE",
    }
    detected_ops = sorted({s for s in decoded_strings if s in known_ops})

    # Detect quantization
    quantization = "UNKNOWN"
    if any("uint8" in s.lower() or "int8" in s.lower() for s in decoded_strings):
        quantization = "INT8"
    elif any("float16" in s.lower() or "fp16" in s.lower() for s in decoded_strings):
        quantization = "FP16"
    elif any("float32" in s.lower() or "fp32" in s.lower() for s in decoded_strings):
        quantization = "FP32"
    elif is_tflite and "quant" in " ".join(decoded_strings).lower():
        quantization = "QUANTIZED"

    # Detect input/output tensor names
    tensor_candidates = [
        s
        for s in decoded_strings
        if re.match(r"^[a-zA-Z0-9_\-\./]+(input|output|logits|prob|dense|image|tokens?)", s, re.I)
    ]
    inputs = [t for t in tensor_candidates if "input" in t.lower() or "image" in t.lower()][:5]
    outputs = [
        t
        for t in tensor_candidates
        if any(k in t.lower() for k in ("output", "logits", "prob", "dense"))
    ][:5]

    # Privacy & Security Sensitivity Heuristics
    sensitive_keywords = {
        "face",
        "biometric",
        "fingerprint",
        "iris",
        "voice",
        "audio",
        "microphone",
        "liveness",
        "ocr",
        "credit_card",
        "financial",
        "medical",
        "passport",
        "license",
        "nude",
        "nsfw",
    }
    found_sensitivities = sorted(
        {kw for kw in sensitive_keywords if any(kw in s.lower() for s in decoded_strings)}
    )

    return {
        "file_name": file_name,
        "file_size": file_size,
        "model_size_bytes": file_size,
        "format": model_format,
        "is_valid_model": model_format != "unknown",
        "quantization": quantization,
        "detected_operators": detected_ops,
        "operators": detected_ops,
        "operator_count": len(detected_ops),
        "inputs": inputs or ["input_tensor_default"],
        "outputs": outputs or ["output_tensor_default"],
        "sensitive_domains": found_sensitivities,
        "has_sensitive_features": len(found_sensitivities) > 0,
        "description": (
            f"On-device {model_format.upper()} model ({quantization}, {file_size} bytes) "
            f"with {len(detected_ops)} operators."
        ),
    }


PROMPT_PATTERNS = [
    r"(?i)(you are an?\s+([a-zA-Z0-9_\-\s]{1,30})?\s*assistant[^\.\n]*)",
    r"(?i)(system\s*(prompt|instructions?)\s*[:=]\s*[\"']?[^\"\n]+[\"']?)",
    r"<\|im_start\|>system\s*([\s\S]*?)<\|im_end\|>",
    r"<<SYS>>\s*([\s\S]*?)<</SYS>>",
    r"\[INST\]\s*<<SYS>>\s*([\s\S]*?)<</SYS>>",
    r"(?i)(instructions?:\s*you must (always|never)[^\.\n]*)",
]

RAG_PATTERNS = [
    r"(?i)(chroma(db)?|faiss|milvus|qdrant|pinecone|weaviate|sqlite-?vec)",
    r"(?i)(similarity_search|vector_store|embedding_function)",
]

PROMPT_INJECTION_RISK = [
    r"(?i)f[\"'].*\{user_input\}.*[\"']",
    r"(?i)prompt\s*(\+|\.concat)\s*user",
    r"(?i)format\s*\(\s*user_input\s*\)",
    r"(?i)(ignore previous instructions|disregard prior instructions|jailbreak)",
]


def extract_ai_prompts(corpus_texts: list[str]) -> dict[str, Any]:
    """Extract embedded system prompts, LLM instructions, and RAG vector configs."""
    combined = "\n".join(corpus_texts)
    extracted_prompts: list[dict[str, Any]] = []

    for pattern in PROMPT_PATTERNS:
        for match in re.finditer(pattern, combined):
            text = match.group(0).strip()
            if len(text) >= 15:
                extracted_prompts.append(
                    {
                        "type": "system_prompt",
                        "snippet": text[:200],
                        "prompt_text": text[:200],
                        "length": len(text),
                    }
                )

    rag_indicators: list[str] = []
    for pattern in RAG_PATTERNS:
        matches = re.findall(pattern, combined)
        for m in matches:
            val = m[0] if isinstance(m, tuple) else m
            if val and val.lower() not in [r.lower() for r in rag_indicators]:
                rag_indicators.append(val)

    injection_risks: list[str] = []
    for pattern in PROMPT_INJECTION_RISK:
        for m in re.finditer(pattern, combined):
            injection_risks.append(m.group(0)[:100])

    return {
        "prompts_found_count": len(extracted_prompts),
        "prompts": extracted_prompts,
        "rag_frameworks": rag_indicators,
        "has_rag_storage": len(rag_indicators) > 0,
        "injection_risks_count": len(injection_risks),
        "injection_risk_snippets": injection_risks,
        "has_prompt_leakage_risk": len(extracted_prompts) > 0,
    }


APPFUNCTION_ANNOTATION_PATTERN = (
    r"@Landroidx/appfunctions/compiler/annotations/AppFunctionDeclaration;"
)
APPFUNCTION_INTERFACE_PATTERN = r"androidx\.appfunctions\.(AppFunction|AppFunctionContext)"


def discover_app_functions(
    manifest_xml: str | None = None,
    smali_sources: list[str] | None = None,
    metadata_xmls: list[str] | None = None,
) -> dict[str, Any]:
    """Discover Android 16 AppFunction declarations exposed to AI agents & system assistants."""
    manifest_xml = manifest_xml or ""
    smali_sources = smali_sources or []
    metadata_xmls = metadata_xmls or []

    functions: list[dict[str, Any]] = []

    # 1. Inspect manifest for AppFunction Service
    has_appfunction_service = (
        "androidx.appfunctions.AppFunctionService" in manifest_xml
        or "android.permission.BIND_APP_FUNCTION_SERVICE" in manifest_xml
    )

    # 2. Inspect smali for AppFunction declarations
    for smali in smali_sources:
        if re.search(APPFUNCTION_ANNOTATION_PATTERN, smali) or re.search(
            APPFUNCTION_INTERFACE_PATTERN, smali
        ):
            # Extract class name
            class_match = re.search(r"\.class\s+.*?(L[a-zA-Z0-9_\$/]+;)", smali)
            class_name = class_match.group(1) if class_match else "unknown"

            # Extract method names annotated with AppFunction
            method_matches = re.findall(
                r"\.method\s+[a-zA-Z0-9_\s]+\s+([a-zA-Z0-9_]+)\(.*?\)L", smali
            )
            for m in method_matches:
                functions.append(
                    {
                        "function_name": m,
                        "class_target": class_name,
                        "source": "smali_annotation",
                        "enabled": True,
                        "requires_auth": "AuthenticationRequired" in smali,
                    }
                )

    # 3. Inspect XML metadata (app_functions.xml or app_metadata.xml)
    for xml in metadata_xmls:
        fn_pattern = r"<(?:appfunction|app-function|function)\s+([^>]+?)(?:/?>)"
        fn_tags = re.findall(fn_pattern, xml, re.IGNORECASE)
        for tag in fn_tags:
            id_match = re.search(r'(?:android:)?id="([^"]+)"', tag)
            fn_id = id_match.group(1) if id_match else "app_fn"
            functions.append(
                {
                    "function_name": fn_id,
                    "class_target": "xml_declaration",
                    "source": "metadata_xml",
                    "enabled": True,
                    "requires_auth": 'requiresAuthentication="true"' in tag,
                }
            )

    return {
        "appfunctions_supported": has_appfunction_service or len(functions) > 0,
        "service_declared": has_appfunction_service,
        "function_count": len(functions),
        "functions_count": len(functions),
        "functions": functions,
        "android_16_ai_agent_ready": len(functions) > 0,
    }
