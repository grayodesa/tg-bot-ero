"""
Utilities for secure file operations.
"""
import os
import shutil
import logging
import tempfile
import contextlib
from typing import Generator, Optional

from config import config

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def secure_tempfile(suffix: Optional[str] = None, prefix: Optional[str] = None) -> Generator[str, None, None]:
    """
    Create a temporary file securely and ensure it gets deleted.
    
    Args:
        suffix: File suffix (e.g. '.jpg')
        prefix: File prefix (e.g. 'avatar_')
        
    Yields:
        Path to the temporary file
    """
    temp_path = None
    try:
        # Create a temporary file in the configured temp directory
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=suffix, 
            prefix=prefix, 
            dir=config.TEMP_DIR
        )
        # Close the file descriptor immediately
        os.close(temp_fd)
        
        # Yield the path to the caller
        yield temp_path
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                # Ensure the file is deleted when context is exited
                os.unlink(temp_path)
                logger.debug(f"Temporary file deleted: {temp_path}")
            except Exception as e:
                logger.error(f"Failed to delete temporary file {temp_path}: {e}")


@contextlib.contextmanager
def secure_tempdir(suffix: Optional[str] = None, prefix: Optional[str] = None) -> Generator[str, None, None]:
    """
    Create a temporary directory securely and ensure it gets deleted.
    
    Args:
        suffix: Directory suffix
        prefix: Directory prefix
        
    Yields:
        Path to the temporary directory
    """
    temp_dir = None
    try:
        # Create a temporary directory in the configured temp directory
        temp_dir = tempfile.mkdtemp(
            suffix=suffix, 
            prefix=prefix, 
            dir=config.TEMP_DIR
        )
        
        # Yield the path to the caller
        yield temp_dir
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try:
                # Ensure the directory is deleted when context is exited
                shutil.rmtree(temp_dir)
                logger.debug(f"Temporary directory deleted: {temp_dir}")
            except Exception as e:
                logger.error(f"Failed to delete temporary directory {temp_dir}: {e}")