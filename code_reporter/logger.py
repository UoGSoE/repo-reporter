"""Logging configuration for Code Reporter."""

import logging
import sys
from typing import Optional


class CodeReporterLogger:
    """Centralized logging for Code Reporter with appropriate output routing."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Set up info and debug loggers with appropriate handlers."""
        # Info logger - goes to stdout for important information
        self.info_logger = logging.getLogger('code_reporter.info')
        self.info_logger.setLevel(logging.INFO)
        
        # Debug logger - goes to stderr for verbose/debug information
        self.debug_logger = logging.getLogger('code_reporter.debug')
        self.debug_logger.setLevel(logging.DEBUG if self.verbose else logging.WARNING)
        
        # Clear any existing handlers
        self.info_logger.handlers.clear()
        self.debug_logger.handlers.clear()
        
        # Info handler - stdout with clean format
        info_handler = logging.StreamHandler(sys.stdout)
        info_handler.setLevel(logging.INFO)
        info_formatter = logging.Formatter('%(message)s')
        info_handler.setFormatter(info_formatter)
        self.info_logger.addHandler(info_handler)
        
        # Debug handler - stderr with timestamps when verbose
        debug_handler = logging.StreamHandler(sys.stderr)
        debug_handler.setLevel(logging.DEBUG if self.verbose else logging.WARNING)
        debug_formatter = logging.Formatter('[%(levelname)s] %(message)s' if self.verbose else '%(message)s')
        debug_handler.setFormatter(debug_formatter)
        self.debug_logger.addHandler(debug_handler)
        
        # Prevent propagation to root logger
        self.info_logger.propagate = False
        self.debug_logger.propagate = False
    
    def info(self, message: str):
        """Log important information to stdout."""
        self.info_logger.info(message)
    
    def debug(self, message: str):
        """Log debug information to stderr (only when verbose)."""
        self.debug_logger.debug(message)
    
    def warning(self, message: str):
        """Log warnings to stderr."""
        self.debug_logger.warning(message)
    
    def error(self, message: str):
        """Log errors to stderr."""
        self.debug_logger.error(message)


# Global logger instance - will be initialized by CLI
logger: Optional[CodeReporterLogger] = None


def get_logger() -> CodeReporterLogger:
    """Get the global logger instance."""
    if logger is None:
        raise RuntimeError("Logger not initialized. Call init_logger() first.")
    return logger


def init_logger(verbose: bool = False) -> CodeReporterLogger:
    """Initialize the global logger instance."""
    global logger
    logger = CodeReporterLogger(verbose)
    return logger