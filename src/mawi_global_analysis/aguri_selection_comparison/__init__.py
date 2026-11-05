"""Independent legacy-BPF versus canonical-input selection comparison."""
from .validation import validate_inputs
from .generation import generate,verify_manifest
__all__=['validate_inputs','generate','verify_manifest']
