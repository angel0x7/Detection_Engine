"""
tetragon_normalize.py

Flattens any Tetragon GetEventsResponse into one common dataclass,
so the detection engine never has to branch on event_type again downstream.
"""

from __future__ import annotations
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from google.protobuf.json_format import MessageToDict

# NOTE: verified against a real `protoc` build of cilium/tetragon's proto
# files - GetEventsResponse (and the request/response envelope types) live
# in events_pb2, NOT tetragon_pb2, even though most message *types* used
# inside it (Process, ProcessKprobe, ProcessLsm, ...) are defined in
# tetragon_pb2. This split is a quirk of how Tetragon organizes its .proto
# files, not a documentation error to "fix" - just import from the right place.
from tetragon.events_pb2 import GetEventsResponse


# ---------------------------------------------------------------------------
# 1. The unified schema
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    exec_id: Optional[str] = None
    pid: Optional[int] = None
    uid: Optional[int] = None
    auid: Optional[int] = None
    binary: Optional[str] = None
    arguments: Optional[str] = None
    cwd: Optional[str] = None
    flags: Optional[str] = None
    start_time: Optional[str] = None
    parent_exec_id: Optional[str] = None
    pod_namespace: Optional[str] = None
    pod_name: Optional[str] = None
    container_id: Optional[str] = None
    container_image: Optional[str] = None
    cap_effective: list = field(default_factory=list)

    @property
    def command_line(self) -> str:
        """Sigma-style single CommandLine field: binary + arguments."""
        if not self.binary:
            return ""
        return f"{self.binary} {self.arguments}".strip()

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> Optional["ProcessInfo"]:
        if not d:
            return None
        pod = d.get("pod", {}) or {}
        container = pod.get("container", {}) or {}
        image = container.get("image", {}) or {}
        cap = d.get("cap", {}) or {}
        return cls(
            exec_id=d.get("exec_id"),
            pid=int(d["pid"]) if "pid" in d else None,
            uid=int(d["uid"]) if "uid" in d else None,
            auid=int(d["auid"]) if "auid" in d else None,
            binary=d.get("binary"),
            arguments=d.get("arguments", ""),
            cwd=d.get("cwd"),
            flags=d.get("flags"),
            start_time=d.get("start_time"),
            parent_exec_id=d.get("parent_exec_id"),
            pod_namespace=pod.get("namespace"),
            pod_name=pod.get("name"),
            container_id=container.get("id"),
            container_image=image.get("name"),
            cap_effective=cap.get("effective", []),
        )


@dataclass
class UnifiedEvent:
    """The single schema every Tetragon event gets flattened into."""
    event_type: str                     # "process_exec", "process_kprobe", ...
    node_name: Optional[str]
    time: Optional[str]

    process: Optional[ProcessInfo] = None
    parent: Optional[ProcessInfo] = None
    ancestors: list = field(default_factory=list)

    # Populated only for hook-based events (kprobe/lsm/tracepoint/uprobe/usdt)
    function_name: Optional[str] = None       # kprobe/lsm function, or uprobe symbol
    policy_name: Optional[str] = None
    action: Optional[str] = None
    args: list = field(default_factory=list)   # normalized KprobeArgument list

    # Populated only for process_exit
    exit_signal: Optional[int] = None
    exit_status: Optional[int] = None

    # Populated only for rate_limit_info / process_throttle
    dropped_events: Optional[int] = None
    throttle_type: Optional[str] = None
    throttle_cgroup: Optional[str] = None

    # Escape hatch: full raw dict, for anything your Sigma rules need
    # that this schema doesn't flatten yet
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 2. Per-event-type normalizers
# ---------------------------------------------------------------------------

def _normalize_args(raw_args: list) -> list:
    """
    KprobeArgument is itself a oneof. MessageToDict already collapses it to
    whichever sub-field was set, e.g. {"pathArg": {...}} or {"sockArg": {...}}.
    We just tag each with its arg_type for easy downstream matching.
    """
    normalized = []
    for a in raw_args or []:
        arg_type = next((k for k in a.keys() if k not in ("index", "label")), None)
        normalized.append({
            "arg_type": arg_type,
            "value": a.get(arg_type) if arg_type else None,
            "index": a.get("index"),
            "label": a.get("label"),
        })
    return normalized


def _base_fields(event_type: str, resp_dict: dict) -> dict:
    return {
        "event_type": event_type,
        "node_name": resp_dict.get("node_name"),
        "time": resp_dict.get("time"),
    }


def normalize_process_exec(event_type, data, resp_dict) -> UnifiedEvent:
    return UnifiedEvent(
        **_base_fields(event_type, resp_dict),
        process=ProcessInfo.from_dict(data.get("process")),
        parent=ProcessInfo.from_dict(data.get("parent")),
        ancestors=[ProcessInfo.from_dict(a) for a in data.get("ancestors", [])],
        raw=data,
    )


def normalize_process_exit(event_type, data, resp_dict) -> UnifiedEvent:
    return UnifiedEvent(
        **_base_fields(event_type, resp_dict),
        process=ProcessInfo.from_dict(data.get("process")),
        parent=ProcessInfo.from_dict(data.get("parent")),
        exit_signal=data.get("signal"),
        exit_status=data.get("status"),
        raw=data,
    )


def normalize_hook_event(event_type, data, resp_dict) -> UnifiedEvent:
    """Shared shape for process_kprobe, process_lsm, process_tracepoint,
    process_uprobe, process_usdt - they all carry process/parent/args/policy."""
    function_name = (
        data.get("function_name")
        or data.get("symbol")           # uprobe
        or data.get("event")            # tracepoint uses subsys+event
        or data.get("name")             # usdt
    )
    return UnifiedEvent(
        **_base_fields(event_type, resp_dict),
        process=ProcessInfo.from_dict(data.get("process")),
        parent=ProcessInfo.from_dict(data.get("parent")),
        ancestors=[ProcessInfo.from_dict(a) for a in data.get("ancestors", [])],
        function_name=function_name,
        policy_name=data.get("policy_name"),
        action=data.get("action"),
        args=_normalize_args(data.get("args", [])),
        raw=data,
    )


def normalize_process_loader(event_type, data, resp_dict) -> UnifiedEvent:
    return UnifiedEvent(
        **_base_fields(event_type, resp_dict),
        process=ProcessInfo.from_dict(data.get("process")),
        function_name=data.get("path"),   # loaded binary path, reuse this slot
        raw=data,
    )


def normalize_process_throttle(event_type, data, resp_dict) -> UnifiedEvent:
    # ProcessThrottle carries no `process` field (only `type` and `cgroup`) -
    # verified against the real proto; do not assume `process` is populated here.
    return UnifiedEvent(
        **_base_fields(event_type, resp_dict),
        throttle_type=data.get("type"),
        throttle_cgroup=data.get("cgroup"),
        raw=data,
    )


def normalize_rate_limit_info(event_type, data, resp_dict) -> UnifiedEvent:
    return UnifiedEvent(
        **_base_fields(event_type, resp_dict),
        dropped_events=int(data.get("number_of_dropped_process_events", 0)),
        raw=data,
    )


# ---------------------------------------------------------------------------
# 3. Dispatch table
# ---------------------------------------------------------------------------

_NORMALIZERS = {
    "process_exec": normalize_process_exec,
    "process_exit": normalize_process_exit,
    "process_kprobe": normalize_hook_event,
    "process_tracepoint": normalize_hook_event,
    "process_uprobe": normalize_hook_event,
    "process_lsm": normalize_hook_event,
    "process_usdt": normalize_hook_event,
    "process_loader": normalize_process_loader,
    "process_throttle": normalize_process_throttle,
    "rate_limit_info": normalize_rate_limit_info,
}


def normalize(resp: GetEventsResponse):
    """Entry point: raw gRPC message -> UnifiedEvent."""
    event_type = resp.WhichOneof("event")
    if event_type is None:
        return None

    inner = getattr(resp, event_type)
    # preserving_proto_field_name=True keeps snake_case (e.g. "path_arg",
    # "exec_id") consistent with proto field names and with every downstream
    # consumer in this project (Sigma field mappings, correlation predicates).
    # Verified: MessageToDict defaults to camelCase, which silently breaks
    # arg_type matching (e.g. "path_arg" vs actual "pathArg") if left unset.
    data = MessageToDict(inner, preserving_proto_field_name=True)
    resp_dict = MessageToDict(resp, preserving_proto_field_name=True)

    normalizer = _NORMALIZERS.get(event_type)
    if normalizer is None:
        # Forward-compatible: unknown future event type, don't crash
        return UnifiedEvent(**_base_fields(event_type, resp_dict), raw=data)

    return normalizer(event_type, data, resp_dict)


# ---------------------------------------------------------------------------
# 4. Streaming client with automatic reconnect
# ---------------------------------------------------------------------------

DEFAULT_SOCKET = "unix:///var/run/tetragon/tetragon.sock"


class StreamError(Exception):
    """The event stream cannot continue and the caller should stop: either a
    fatal gRPC status (wrong API, bad request) or max_retries consecutive
    failed reconnect attempts."""


class _ConnectFailed(Exception):
    pass


def _socket_path(socket_path: str) -> Optional[str]:
    """'unix:///var/run/x.sock' -> '/var/run/x.sock'; None for non-unix targets."""
    if not socket_path.startswith("unix:"):
        return None
    path = socket_path[len("unix:"):]
    return path[2:] if path.startswith("//") else path


def _socket_problem(socket_path: str) -> str:
    """Cheap, human-readable diagnosis for the two most common failures."""
    path = _socket_path(socket_path)
    if path is None:
        return ""
    if not os.path.exists(path):
        return f"socket {path} does not exist - is the tetragon daemon running?"
    if not os.access(path, os.R_OK | os.W_OK):
        return (f"no permission on {path} - run with sudo, or adjust the "
                f"socket's permissions")
    return ""


def _default_status(state: str, **info):
    detail = " ".join(f"{k}={v}" for k, v in info.items() if v is not None)
    print(f"[stream] {state} {detail}".rstrip(), file=sys.stderr, flush=True)


def stream_events(socket_path: str = DEFAULT_SOCKET,
                  on_status=None,
                  max_retries: Optional[int] = None,
                  initial_backoff: float = 1.0,
                  max_backoff: float = 30.0,
                  connect_timeout: float = 5.0):
    """
    Yield UnifiedEvents from Tetragon's GetEvents stream, reconnecting
    automatically (exponential backoff: initial_backoff, x2, capped at
    max_backoff) if the daemon is down, restarts, or drops the stream.

    on_status(state, **info) is called on connection changes:
      "connected"    socket, blind_seconds (None on first connect, else the
                     length of the gap during which NO events were seen)
      "disconnected" reason
      "reconnecting" attempt, delay, reason
      "fatal"        reason (just before StreamError is raised)
      "event_error"  error (one event failed to normalize and was skipped)

    max_retries=None retries forever. Otherwise StreamError is raised after
    that many consecutive failed attempts (0 = do not retry at all). A
    successful connection resets the counter.

    These gRPC codes (UNIMPLEMENTED, INVALID_ARGUMENT,
    UNAUTHENTICATED, PERMISSION_DENIED) are fatal and never retried: retrying cannot fix them.
    """
    import grpc
    from tetragon.events_pb2 import GetEventsRequest
    from tetragon.sensors_pb2_grpc import FineGuidanceSensorsStub

    fatal_codes = {
        grpc.StatusCode.UNIMPLEMENTED,
        grpc.StatusCode.INVALID_ARGUMENT,
        grpc.StatusCode.UNAUTHENTICATED,
        grpc.StatusCode.PERMISSION_DENIED,
    }
    notify = on_status or _default_status
    failures = 0
    down_since = None

    while True:
        channel = grpc.insecure_channel(socket_path)
        call = None
        try:
            problem = _socket_problem(socket_path)
            if problem.startswith("socket ") and "does not exist" in problem:
                raise _ConnectFailed(problem)          # fail fast, no 5s wait
            try:
                grpc.channel_ready_future(channel).result(timeout=connect_timeout)
            except grpc.FutureTimeoutError:
                msg = f"could not connect within {connect_timeout:g}s"
                raise _ConnectFailed(f"{msg}; {problem}" if problem else msg)

            gap = None if down_since is None else time.monotonic() - down_since
            notify("connected", socket=socket_path, blind_seconds=gap)
            down_since, failures = None, 0

            call = FineGuidanceSensorsStub(channel).GetEvents(GetEventsRequest())
            for resp in call:
                try:
                    event = normalize(resp)
                except Exception as exc:               # one bad event must not kill detection
                    notify("event_error", error=f"{type(exc).__name__}: {exc}")
                    continue
                if event is not None:
                    yield event
            reason = "stream closed by the daemon"
        except _ConnectFailed as exc:
            reason = str(exc)
        except grpc.RpcError as exc:
            if exc.code() in fatal_codes:
                reason = f"{exc.code().name}: {exc.details()}"
                notify("fatal", reason=reason)
                raise StreamError(reason) from exc
            reason = f"{exc.code().name}: {exc.details()}"
            problem = _socket_problem(socket_path)
            if problem:
                reason += f" ({problem})"
        finally:
            if call is not None:
                call.cancel()
            channel.close()

        if down_since is None:
            down_since = time.monotonic()
            notify("disconnected", reason=reason)
        failures += 1
        if max_retries is not None and failures > max_retries:
            notify("fatal", reason=reason)
            raise StreamError(f"giving up after {max_retries} retries: {reason}")
        delay = min(max_backoff, initial_backoff * 2 ** (failures - 1))
        notify("reconnecting", attempt=failures, delay=round(delay, 2), reason=reason)
        time.sleep(delay)


if __name__ == "__main__":
    for evt in stream_events():
        print(evt.event_type, "|",
              evt.process.command_line if evt.process else None,
              "| function:", evt.function_name,
              "| policy:", evt.policy_name)
