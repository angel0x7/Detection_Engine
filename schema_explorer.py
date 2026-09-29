"""
schema_explorer.py

Walks the compiled protobuf descriptors directly to print every event type's
field structure - no daemon connection needed. Useful as a reference catalogue
before/alongside live event capture.

Usage:
    python3 schema_explorer.py              # all event types in GetEventsResponse
    python3 schema_explorer.py process_kprobe   # just one
    python3 schema_explorer.py --args       # also dump the KprobeArgument oneof
"""

import sys

from google.protobuf.descriptor import FieldDescriptor
from tetragon import events_pb2

# Map protobuf's numeric TYPE_* constants to readable names.
# Built from FieldDescriptor itself so it stays correct across protobuf versions.
_TYPE_NAMES = {
    getattr(FieldDescriptor, name): name[len("TYPE_"):].lower()
    for name in dir(FieldDescriptor)
    if name.startswith("TYPE_")
}


def describe_field(f) -> str:
    """Human-readable type for a FieldDescriptor (message, enum, or scalar)."""
    if f.message_type is not None:
        base = f.message_type.name
    elif f.enum_type is not None:
        base = f"enum {f.enum_type.name}"
    else:
        base = _TYPE_NAMES.get(f.type, f"type#{f.type}")

    # `is_repeated` exists on newer protobuf; older builds use label.
    repeated = getattr(f, "is_repeated", None)
    if repeated is None:
        repeated = f.label == FieldDescriptor.LABEL_REPEATED
    return f"repeated {base}" if repeated else base


def print_message(desc, indent: str = "  "):
    for f in desc.fields:
        print(f"{indent}{f.number:>3}  {f.name}: {describe_field(f)}")


def print_oneof_message(desc, oneof_name: str):
    oneof = desc.oneofs_by_name[oneof_name]
    for f in oneof.fields:
        if f.message_type is None:
            # Scalar/enum member of the oneof (e.g. KprobeArgument.string_arg):
            # no nested structure to expand, just show its type on one line.
            print(f"  {f.number:>3}  {f.name}: {describe_field(f)}")
            continue
        print(f"--- {f.name} ({f.message_type.name}) ---")
        print_message(f.message_type)
        print()


def find_event(name: str):
    oneof = events_pb2.GetEventsResponse.DESCRIPTOR.oneofs_by_name["event"]
    for f in oneof.fields:
        if f.name == name:
            return f
    return None


def main():
    args = sys.argv[1:]
    desc = events_pb2.GetEventsResponse.DESCRIPTOR

    print("=== GetEventsResponse envelope (non-oneof fields) ===")
    for f in desc.fields:
        if f.containing_oneof is None:
            print(f"  {f.number:>3}  {f.name}: {describe_field(f)}")
    print()

    if args and not args[0].startswith("--"):
        f = find_event(args[0])
        if f is None:
            valid = [x.name for x in desc.oneofs_by_name["event"].fields]
            print(f"Unknown event type '{args[0]}'. Valid: {', '.join(valid)}")
            sys.exit(1)
        print(f"--- {f.name} ({f.message_type.name}) ---")
        print_message(f.message_type)
        return

    print("=== event oneof ===")
    print_oneof_message(desc, "event")

    if "--args" in args:
        from tetragon import tetragon_pb2
        print("=== KprobeArgument oneof (arg types your policies can emit) ===")
        print_oneof_message(tetragon_pb2.KprobeArgument.DESCRIPTOR, "arg")


if __name__ == "__main__":
    main()
