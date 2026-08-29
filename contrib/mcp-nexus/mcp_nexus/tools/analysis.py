"""Host-side tabular analysis tools built on reusable remote Python sandboxes."""

from __future__ import annotations

import json
import shlex
import time
from typing import Any
from uuid import uuid4

from mcp.server.fastmcp import FastMCP

from mcp_nexus.python_execution import numeric_thread_env, write_secret_file
from mcp_nexus.python_sandbox import ensure_python_sandbox, sandbox_path
from mcp_nexus.results import ToolResult, build_tool_result
from mcp_nexus.runtime import ExecutionLimits, ExecutionRequest, build_managed_command, extract_execution_metadata
from mcp_nexus.server import get_artifacts, get_pool, get_settings, tool_context
from mcp_nexus.tools.database import _resolve_sql_text
from mcp_nexus.transport.ssh import CommandResult

TABULAR_ANALYSIS_REQUIREMENTS = ("numpy", "pandas", "scikit-learn", "psycopg[binary]")
TABULAR_ANALYSIS_SANDBOX = "tabular-analysis"


def _result(
    tool_name: str,
    *,
    ok: bool,
    duration_ms: float,
    stdout_text: str = "",
    stderr_text: str = "",
    error_code: str | None = None,
    error_stage: str | None = None,
    message: str | None = None,
    exit_code: int | None = None,
    data: Any = None,
    usage: dict[str, Any] | None = None,
) -> ToolResult:
    settings = get_settings()
    return build_tool_result(
        context=tool_context(tool_name),
        artifacts=get_artifacts(),
        ok=ok,
        duration_ms=duration_ms,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        output_limit=settings.output_limit_bytes,
        error_limit=settings.error_limit_bytes,
        output_preview_limit=settings.output_preview_bytes,
        error_preview_limit=settings.error_preview_bytes,
        error_code=error_code,
        error_stage=error_stage,
        message=message,
        exit_code=exit_code,
        data=data,
        resource_usage=usage,
    )


def _error_code_for_result(result: CommandResult) -> tuple[str | None, str | None]:
    if result.ok:
        return None, None
    stderr = result.stderr.lower()
    if result.exit_code == 124 or "timed out" in stderr:
        return "TIMEOUT", "execution"
    return "COMMAND_FAILED", "execution"


def _analysis_source(
    *,
    csv_path: str = "",
    query: str = "",
    sql: str = "",
) -> dict[str, Any]:
    has_csv = bool(csv_path.strip())
    has_query = bool(query.strip() or sql.strip())
    if has_csv == has_query:
        raise ValueError("Provide either csv_path or query/sql.")
    if has_csv:
        return {"kind": "csv", "csv_path": get_settings().expanded_path(csv_path)}
    return {"kind": "sql", "query": _resolve_sql_text(query=query, sql=sql)}


def _resolve_db_uri(*, profile: str = "", database: str = "") -> str:
    settings = get_settings()
    resolved = settings.resolve_requested_db_profile(
        profile_name=profile.strip(),
        database=database,
        execution_backend=str(get_pool().backend_metadata()["backend_kind"]),
    )
    if resolved is None:
        raise LookupError(
            f"Database profile {profile!r} was not found." if profile.strip() else "No database profile is configured."
        )
    return resolved.dsn


async def _run_analysis_job(
    tool_name: str,
    *,
    payload: dict[str, Any],
    timeout: int,
) -> tuple[CommandResult, dict[str, Any] | None, float]:
    sandbox_info, _ = await ensure_python_sandbox(
        sandbox_path_value=sandbox_path(name=TABULAR_ANALYSIS_SANDBOX),
        requirements=list(TABULAR_ANALYSIS_REQUIREMENTS),
    )
    pool = get_pool()
    conn = await pool.acquire()
    script_path = f"/tmp/{tool_name}-{uuid4().hex}.py"
    payload_path = f"/tmp/{tool_name}-{uuid4().hex}.json"
    db_uri_path = ""
    try:
        capabilities = await conn.probe_capabilities()
        if not capabilities.python_command:
            raise RuntimeError("Python is not available on the target host.")

        python_bin = str(sandbox_info["python"])
        runtime_payload = dict(payload)
        thread_limit = max(1, get_settings().analysis_thread_limit)
        runtime_env = {
            "VIRTUAL_ENV": str(sandbox_info["path"]),
            "PATH": f"{sandbox_info['path']}/bin:$PATH",
            **numeric_thread_env(thread_limit),
        }
        db_uri = str(runtime_payload.pop("db_uri", "") or "")
        if db_uri:
            db_uri_path = await write_secret_file(conn, prefix=f"{tool_name}-db", content=db_uri)
            runtime_payload["db_uri_path"] = db_uri_path
        runtime_payload["execution_policy"] = {
            "numeric_thread_limit": thread_limit,
            "database_delivery": "secret_file" if db_uri_path else None,
        }
        await conn.write_file(script_path, _analysis_script())
        await conn.write_file(payload_path, json.dumps(runtime_payload, ensure_ascii=True))

        request = ExecutionRequest(
            command=f"{shlex.quote(python_bin)} {shlex.quote(script_path)} {shlex.quote(payload_path)}",
            cwd=_safe_analysis_cwd(),
            timeout=timeout,
            env=runtime_env,
            capture_usage=True,
            limits=ExecutionLimits(cpu_seconds=max(60, min(timeout, 900)), memory_mb=1024),
        )
        started = time.monotonic()
        raw_result = await conn.run_full(build_managed_command(capabilities, request), timeout=timeout)
        duration_ms = (time.monotonic() - started) * 1000
        stderr, usage = extract_execution_metadata(raw_result.stderr)
        return (
            CommandResult(stdout=raw_result.stdout, stderr=stderr, exit_code=raw_result.exit_code),
            usage,
            duration_ms,
        )
    finally:
        try:
            cleanup_paths = [script_path, payload_path, *([db_uri_path] if db_uri_path else [])]
            await conn.run_full(
                "rm -f " + " ".join(shlex.quote(path) for path in cleanup_paths),
                timeout=20,
            )
        finally:
            pool.release(conn)


def _safe_analysis_cwd() -> str:
    settings = get_settings()
    return settings.expanded_path(settings.default_cwd)


def _analysis_script() -> str:
    return r"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split


def _load_payload() -> dict:
    return json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))


def _load_db_uri(spec: dict) -> str:
    db_uri_path = str(spec.get("db_uri_path") or "")
    if not db_uri_path:
        raise ValueError("db_uri_path is required for SQL sources")
    path = Path(db_uri_path)
    try:
        return path.read_text(encoding="utf-8").strip()
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _load_frame(spec: dict) -> pd.DataFrame:
    if spec["kind"] == "csv":
        return pd.read_csv(spec["csv_path"])

    import psycopg

    uri = _load_db_uri(spec)
    with psycopg.connect(uri) as conn:
        return pd.read_sql_query(spec["query"], conn)


def _infer_datetime_columns(
    frame: pd.DataFrame,
    columns: list[str],
    threshold: float,
) -> tuple[list[str], dict[str, pd.Series]]:
    detected: list[str] = []
    parsed: dict[str, pd.Series] = {}
    for column in columns:
        series = frame[column]
        if pd.api.types.is_datetime64_any_dtype(series):
            detected.append(column)
            parsed[column] = pd.to_datetime(series, errors="coerce")
            continue
        coerced = pd.to_datetime(series, errors="coerce", utc=False)
        if float(coerced.notna().mean()) >= threshold:
            detected.append(column)
            parsed[column] = coerced
    return detected, parsed


def _combine_text_columns(frame: pd.DataFrame, columns: list[str]) -> list[str]:
    if not columns:
        return ["" for _ in range(len(frame))]
    values = frame[columns].fillna("").astype(str)
    documents: list[str] = []
    for row in values.itertuples(index=False, name=None):
        parts = []
        for column, value in zip(columns, row):
            cleaned = value.strip()
            if cleaned:
                parts.append(f"{column} {cleaned}")
        documents.append(" ".join(parts))
    return documents


def _json_ready(value):
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if pd.isna(value):
        return None
    if isinstance(value, (np.generic,)):
        return value.item()
    return value


def _profile_dataset(payload: dict, frame: pd.DataFrame) -> dict:
    target_column = payload.get("target_column") or ""
    sample_rows = int(payload.get("sample_rows") or 5)
    numeric_columns = [column for column in frame.columns if pd.api.types.is_numeric_dtype(frame[column])]
    remaining = [column for column in frame.columns if column not in numeric_columns]
    datetime_columns, _ = _infer_datetime_columns(frame, remaining, float(payload.get("datetime_threshold") or 0.9))
    text_columns = [column for column in remaining if column not in datetime_columns]
    column_profiles = []
    for column in frame.columns:
        series = frame[column]
        value_counts = series.astype(str).value_counts(dropna=False).head(5)
        column_profiles.append(
            {
                "column": column,
                "dtype": str(series.dtype),
                "missing_ratio": float(series.isna().mean()),
                "unique_count": int(series.nunique(dropna=True)),
                "top_values": [{"value": value, "count": int(count)} for value, count in value_counts.items()],
            }
        )

    report = {
        "mode": "profile",
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "target_column": target_column or None,
        "execution_policy": payload.get("execution_policy") or {},
        "numeric_columns": numeric_columns,
        "datetime_columns": datetime_columns,
        "text_columns": text_columns,
        "column_profiles": column_profiles,
        "sample_rows": _json_ready(frame.head(max(1, min(sample_rows, 20))).to_dict(orient="records")),
        "inference_policy": {
            "datetime_threshold": float(payload.get("datetime_threshold") or 0.9),
            "text_strategy": "all non-numeric, non-datetime columns are fused into a single text document per row",
        },
    }
    if target_column and target_column in frame.columns:
        target_counts = frame[target_column].astype(str).value_counts(dropna=False)
        report["target_distribution"] = [
            {"label": label, "count": int(count)}
            for label, count in target_counts.items()
        ]
    return report


def _train_classifier(payload: dict, frame: pd.DataFrame) -> dict:
    target_column = str(payload["target_column"])
    if target_column not in frame.columns:
        raise ValueError(f"target_column {target_column!r} was not found")

    drop_columns = [
        column
        for column in payload.get("drop_columns", [])
        if column in frame.columns and column != target_column
    ]
    work = frame.dropna(subset=[target_column]).copy()
    y_raw = work[target_column].astype(str)
    classes = sorted(y_raw.unique().tolist())
    if len(classes) < 2:
        raise ValueError("target_column must contain at least two classes")

    positive_label = str(payload.get("positive_label") or "")
    if positive_label and positive_label not in classes:
        raise ValueError(f"positive_label {positive_label!r} was not found in target_column")
    is_binary = len(classes) == 2

    feature_frame = work.drop(columns=[target_column, *drop_columns], errors="ignore")
    numeric_columns = [
        column
        for column in feature_frame.columns
        if pd.api.types.is_numeric_dtype(feature_frame[column])
    ]
    remaining = [column for column in feature_frame.columns if column not in numeric_columns]
    datetime_columns, parsed_datetimes = _infer_datetime_columns(
        feature_frame,
        remaining,
        float(payload.get("datetime_threshold") or 0.9),
    )
    text_columns = [column for column in remaining if column not in datetime_columns]

    dense_arrays = []
    dense_feature_names = []
    if numeric_columns:
        numeric = feature_frame[numeric_columns].apply(pd.to_numeric, errors="coerce")
        numeric = numeric.fillna(numeric.median()).fillna(0.0)
        dense_arrays.append(numeric.to_numpy(dtype=float))
        dense_feature_names.extend(numeric_columns)

    for column in datetime_columns:
        parsed = parsed_datetimes[column]
        dt_features = np.column_stack(
            [
                parsed.dt.year.fillna(-1).to_numpy(dtype=float),
                parsed.dt.month.fillna(-1).to_numpy(dtype=float),
                parsed.dt.day.fillna(-1).to_numpy(dtype=float),
                parsed.dt.hour.fillna(-1).to_numpy(dtype=float),
                parsed.dt.dayofweek.fillna(-1).to_numpy(dtype=float),
            ]
        )
        dense_arrays.append(dt_features)
        dense_feature_names.extend(
            [
                f"{column}__year",
                f"{column}__month",
                f"{column}__day",
                f"{column}__hour",
                f"{column}__dow",
            ]
        )

    if dense_arrays:
        dense_matrix = sparse.csr_matrix(np.concatenate(dense_arrays, axis=1))
    else:
        dense_matrix = sparse.csr_matrix((len(feature_frame), 0))

    documents = _combine_text_columns(feature_frame, text_columns)
    has_text = any(document.strip() for document in documents)
    text_feature_names: list[str] = []
    vectorizer = None
    if has_text:
        vectorizer = TfidfVectorizer(
            max_features=int(payload.get("max_text_features") or 2048),
            ngram_range=(1, 2),
            min_df=2,
        )
        try:
            text_matrix = vectorizer.fit_transform(documents)
        except ValueError:
            text_matrix = sparse.csr_matrix((len(feature_frame), 0))
            vectorizer = None
        else:
            text_feature_names = [f"text::{name}" for name in vectorizer.get_feature_names_out()]
    else:
        text_matrix = sparse.csr_matrix((len(feature_frame), 0))

    X = sparse.hstack([dense_matrix, text_matrix], format="csr")
    if X.shape[1] == 0:
        raise ValueError("No usable features were derived from the dataset")

    if is_binary:
        positive = positive_label or classes[-1]
        y = (y_raw == positive).astype(int)
        label_names = ["not_positive", positive]
    else:
        positive = None
        y = y_raw
        label_names = classes

    test_size = float(payload.get("test_size") or 0.25)
    random_state = int(payload.get("random_state") or 42)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model = LogisticRegression(
        max_iter=int(payload.get("max_iter") or 1000),
        class_weight="balanced",
        solver="saga",
        random_state=random_state,
        n_jobs=1,
    )
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "macro_f1": float(f1_score(y_test, pred, average="macro")),
        "weighted_f1": float(f1_score(y_test, pred, average="weighted")),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "classification_report": _json_ready(classification_report(y_test, pred, output_dict=True, zero_division=0)),
        "class_labels": _json_ready(label_names),
    }
    majority_class = y_train.value_counts().idxmax()
    majority_pred = np.full(shape=len(y_test), fill_value=majority_class)
    baseline = {
        "strategy": "predict_majority_class",
        "accuracy": float(accuracy_score(y_test, majority_pred)),
        "macro_f1": float(f1_score(y_test, majority_pred, average="macro")),
    }
    if is_binary:
        proba = model.predict_proba(X_test)[:, 1]
        metrics["positive_label"] = positive
        metrics["roc_auc"] = float(roc_auc_score(y_test, proba))

    feature_names = dense_feature_names + text_feature_names
    feature_weights = []
    if hasattr(model, "coef_") and model.coef_.ndim == 2:
        if model.coef_.shape[0] == 1:
            weights = model.coef_[0]
            ranking = np.argsort(np.abs(weights))[::-1][: int(payload.get("top_features") or 20)]
            feature_weights = [
                {
                    "feature": feature_names[index],
                    "weight": float(weights[index]),
                    "direction": "positive" if weights[index] >= 0 else "negative",
                }
                for index in ranking
            ]

    report = {
        "mode": "train_classifier",
        "dataset": {
            "rows": int(len(work)),
            "feature_columns": int(X.shape[1]),
            "train_rows": int(X_train.shape[0]),
            "test_rows": int(X_test.shape[0]),
            "classes": _json_ready(classes),
        },
        "source_columns": {
            "numeric": numeric_columns,
            "datetime": datetime_columns,
            "text": text_columns,
            "dropped": drop_columns,
        },
        "model": {
            "type": "LogisticRegression",
            "solver": "saga",
            "class_weight": "balanced",
            "max_iter": int(payload.get("max_iter") or 1000),
        },
        "execution_policy": payload.get("execution_policy") or {},
        "baseline": baseline,
        "metrics": metrics,
        "top_feature_weights": feature_weights,
        "inference_policy": {
            "datetime_threshold": float(payload.get("datetime_threshold") or 0.9),
            "text_strategy": "all non-numeric, non-datetime columns are fused into a TF-IDF document per row",
        },
    }
    report_path = str(payload.get("report_path") or "")
    if report_path:
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        report["report_path"] = report_path
    return report


def main() -> None:
    payload = _load_payload()
    frame = _load_frame(payload["source"])
    if payload["mode"] == "profile":
        report = _profile_dataset(payload, frame)
    elif payload["mode"] == "train_classifier":
        report = _train_classifier(payload, frame)
    else:
        raise ValueError(f"Unsupported mode: {payload['mode']!r}")
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
""".strip()


def register(mcp: FastMCP):

    @mcp.tool(structured_output=True)
    async def tabular_dataset_profile(
        csv_path: str = "",
        query: str = "",
        sql: str = "",
        profile: str = "",
        database: str = "",
        target_column: str = "",
        sample_rows: int = 5,
        datetime_threshold: float = 0.9,
        timeout: int = 300,
    ) -> ToolResult:
        """Profile a CSV file or SQL result set into a compact, model-oriented dataset summary."""
        started = time.monotonic()
        try:
            source = _analysis_source(csv_path=csv_path, query=query, sql=sql)
        except ValueError as exc:
            return _result(
                "tabular_dataset_profile",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="INVALID_SOURCE",
                error_stage="validation",
                message=str(exc),
            )

        payload = {
            "mode": "profile",
            "source": source,
            "target_column": target_column.strip(),
            "sample_rows": max(1, min(sample_rows, 20)),
            "datetime_threshold": max(0.5, min(datetime_threshold, 1.0)),
        }
        if source["kind"] == "sql":
            try:
                payload["db_uri"] = _resolve_db_uri(profile=profile, database=database)
            except (LookupError, ValueError) as exc:
                return _result(
                    "tabular_dataset_profile",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="DB_PROFILE_NOT_FOUND" if isinstance(exc, LookupError) else "INVALID_DATABASE_URI",
                    error_stage="configuration" if isinstance(exc, LookupError) else "validation",
                    message=str(exc),
                )

        try:
            result, usage, duration_ms = await _run_analysis_job(
                "tabular_dataset_profile",
                payload=payload,
                timeout=max(60, min(timeout, 900)),
            )
        except Exception as exc:
            return _result(
                "tabular_dataset_profile",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="ANALYSIS_SETUP_FAILED",
                error_stage="setup",
                message=str(exc),
            )

        error_code, error_stage = _error_code_for_result(result)
        data = None
        if result.ok and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                error_code = "ANALYSIS_OUTPUT_INVALID"
                error_stage = "parsing"
                return _result(
                    "tabular_dataset_profile",
                    ok=False,
                    duration_ms=duration_ms,
                    stdout_text=result.stdout,
                    stderr_text=result.stderr,
                    error_code=error_code,
                    error_stage=error_stage,
                    message="Dataset profiling returned non-JSON output.",
                    exit_code=result.exit_code,
                    usage=usage,
                )
        return _result(
            "tabular_dataset_profile",
            ok=result.ok,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Dataset profiling failed.",
            exit_code=result.exit_code,
            data=data,
            usage=usage,
        )

    @mcp.tool(structured_output=True)
    async def train_tabular_classifier(
        target_column: str,
        csv_path: str = "",
        query: str = "",
        sql: str = "",
        profile: str = "",
        database: str = "",
        drop_columns: list[str] | None = None,
        positive_label: str = "",
        report_path: str = "",
        test_size: float = 0.25,
        random_state: int = 42,
        max_iter: int = 1000,
        max_text_features: int = 2048,
        top_features: int = 20,
        datetime_threshold: float = 0.9,
        timeout: int = 600,
    ) -> ToolResult:
        """Train a general tabular classifier from CSV or SQL without embedding ad-hoc Python in tool args."""
        started = time.monotonic()
        if not target_column.strip():
            return _result(
                "train_tabular_classifier",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="TARGET_REQUIRED",
                error_stage="validation",
                message="target_column is required",
            )

        try:
            source = _analysis_source(csv_path=csv_path, query=query, sql=sql)
        except ValueError as exc:
            return _result(
                "train_tabular_classifier",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="INVALID_SOURCE",
                error_stage="validation",
                message=str(exc),
            )

        payload = {
            "mode": "train_classifier",
            "source": source,
            "target_column": target_column.strip(),
            "drop_columns": sorted({column for column in (drop_columns or []) if column.strip()}),
            "positive_label": positive_label.strip(),
            "report_path": get_settings().expanded_path(report_path) if report_path.strip() else "",
            "test_size": max(0.05, min(test_size, 0.5)),
            "random_state": random_state,
            "max_iter": max(100, min(max_iter, 5000)),
            "max_text_features": max(128, min(max_text_features, 10000)),
            "top_features": max(1, min(top_features, 100)),
            "datetime_threshold": max(0.5, min(datetime_threshold, 1.0)),
        }
        if source["kind"] == "sql":
            try:
                payload["db_uri"] = _resolve_db_uri(profile=profile, database=database)
            except (LookupError, ValueError) as exc:
                return _result(
                    "train_tabular_classifier",
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000,
                    error_code="DB_PROFILE_NOT_FOUND" if isinstance(exc, LookupError) else "INVALID_DATABASE_URI",
                    error_stage="configuration" if isinstance(exc, LookupError) else "validation",
                    message=str(exc),
                )

        try:
            result, usage, duration_ms = await _run_analysis_job(
                "train_tabular_classifier",
                payload=payload,
                timeout=max(120, min(timeout, 1800)),
            )
        except Exception as exc:
            return _result(
                "train_tabular_classifier",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                error_code="ANALYSIS_SETUP_FAILED",
                error_stage="setup",
                message=str(exc),
            )

        error_code, error_stage = _error_code_for_result(result)
        data = None
        if result.ok and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                error_code = "ANALYSIS_OUTPUT_INVALID"
                error_stage = "parsing"
                return _result(
                    "train_tabular_classifier",
                    ok=False,
                    duration_ms=duration_ms,
                    stdout_text=result.stdout,
                    stderr_text=result.stderr,
                    error_code=error_code,
                    error_stage=error_stage,
                    message="Tabular model training returned non-JSON output.",
                    exit_code=result.exit_code,
                    usage=usage,
                )
        return _result(
            "train_tabular_classifier",
            ok=result.ok,
            duration_ms=duration_ms,
            stdout_text=result.stdout,
            stderr_text=result.stderr,
            error_code=error_code,
            error_stage=error_stage,
            message=None if result.ok else "Tabular model training failed.",
            exit_code=result.exit_code,
            data=data,
            usage=usage,
        )
