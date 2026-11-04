"""Read-only validation of saved canonical-input RLS weight comparisons."""
from .validation import ComparisonValidationError, validate_comparison

__all__ = ['ComparisonValidationError', 'validate_comparison']
