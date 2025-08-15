#!/usr/bin/env python3
"""
Code Reporter - Main Entry Point

A comprehensive tool for analyzing GitHub repositories and generating
detailed reports on code quality, security, dependencies, and error tracking.

Usage:
    python main.py --repo-list-file repos.txt --output-dir reports
    
Or use the module directly:
    python -m code_reporter.cli --repo-list-file repos.txt
"""

if __name__ == "__main__":
    # Import and run the CLI
    from code_reporter.cli import main
    main()