"""
tetragon_pipeline.py

Maps Sigma's generic field names onto UnifiedEvent fields.
"""

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation


def tetragon_pipeline() -> ProcessingPipeline:
    field_mappings = {
        # Sigma field -> our UnifiedEvent dotted path
        "Image":              "process.binary",
        "CommandLine":        "process.command_line",
        "ParentImage":        "parent.binary",
        "ParentCommandLine":  "parent.command_line",
        "User":               "process.uid",
        "auid":               "process.auid",   # login/audit uid - NOT auto-mapped from "User";
                                                  # any Sigma rule field not listed here silently
                                                  # resolves to None. Verified via testing: an
                                                  # unmapped field name means "not filter"-style
                                                  # exclusions always evaluate to True (never exclude).
        "CurrentDirectory":   "process.cwd",
        "TargetFilename":     "args.path_arg.path",     # from kprobe file/path args
        "DestinationIp":      "args.sock_arg.daddr",
        "DestinationPort":    "args.sock_arg.dport",
        "Protocol":           "args.sock_arg.protocol",
        # Positional arguments: '<position>.<arg_type>' = the Nth argument of the
        # event, needed when a hook has several args of the same type.
        # These match tracingpolicies/ptrace-injection.yaml (arg 0 = request, arg 1 = pid).
        "PtraceRequest":      "args.0.int_arg",
        "PtraceTargetPid":    "args.1.int_arg",
        # add more as you build TracingPolicies and know their arg shapes
    }

    return ProcessingPipeline(
        name="tetragon_pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="tetragon_field_mapping",
                transformation=FieldMappingTransformation(field_mappings),
            ),
        ],
    )
