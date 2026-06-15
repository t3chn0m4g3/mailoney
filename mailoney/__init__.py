"""
Mailoney - A Simple SMTP Honeypot with JSON logging
"""
__author__ = 'awhitehatter'
__version__ = '2.2.0'

# Import key components to make them available at package level
from .core import SMTPHoneypot, run_server
from .config import get_settings, configure_logging
