"""Repository cloning and management functionality."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager

import git
from git import Repo
from .logger import get_logger


class RepositoryManager:
    """Handles repository cloning, access, and cleanup."""
    
    def __init__(self, github_token: Optional[str] = None):
        # Note: github_token parameter kept for backwards compatibility but not used
        # gh CLI handles authentication automatically
        self.temp_dirs: List[Path] = []
        # Verify gh CLI is available
        self._verify_gh_cli()
    
    def _verify_gh_cli(self):
        """Verify that gh CLI is available."""
        try:
            subprocess.run(
                ['gh', '--version'],
                capture_output=True,
                text=True,
                check=True
            )
        except FileNotFoundError:
            raise RuntimeError("gh CLI not found. Please install GitHub CLI.")
        except subprocess.CalledProcessError:
            raise RuntimeError("gh CLI is installed but not working properly.")
    
    @contextmanager
    def clone_repositories(self, repo_urls: List[str], progress_callback=None):
        """
        Clone multiple repositories and yield a mapping of URL to local path.
        
        Args:
            repo_urls: List of GitHub repository URLs
            progress_callback: Optional callback function for progress updates
            
        Yields:
            Dict mapping repository URL to RepoInfo
        """
        repo_info = {}
        
        try:
            for i, url in enumerate(repo_urls):
                if progress_callback:
                    progress_callback(f"Cloning {url} ({i+1}/{len(repo_urls)})")
                
                info = self._clone_single_repo(url)
                repo_info[url] = info
                
            yield repo_info
            
        finally:
            # Cleanup all temporary directories
            self.cleanup()
    
    def _clone_single_repo(self, repo_url: str) -> 'RepoInfo':
        """
        Clone a single repository and return information about it.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            RepoInfo object with clone status and path information
        """
        # Create temporary directory
        temp_dir = Path(tempfile.mkdtemp(prefix="code-reporter-"))
        self.temp_dirs.append(temp_dir)
        
        try:
            # Use gh CLI to clone repository (handles both public and private repos)
            result = subprocess.run(
                ['gh', 'repo', 'clone', repo_url, str(temp_dir)],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Open the cloned repository with GitPython for metadata access
            repo = Repo(temp_dir)
            
            return RepoInfo(
                url=repo_url,
                local_path=temp_dir,
                success=True,
                error=None,
                repo=repo
            )
            
        except Exception as e:
            return RepoInfo(
                url=repo_url,
                local_path=temp_dir,
                success=False,
                error=str(e),
                repo=None
            )
    
    
    def cleanup(self):
        """Remove all temporary directories."""
        for temp_dir in self.temp_dirs:
            if temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger = get_logger()
                    logger.warning(f"Failed to cleanup {temp_dir}: {e}")
        
        self.temp_dirs.clear()


class RepoInfo:
    """Information about a cloned repository."""
    
    def __init__(self, url: str, local_path: Path, success: bool, error: Optional[str], repo: Optional[Repo]):
        self.url = url
        self.local_path = local_path
        self.success = success
        self.error = error
        self.repo = repo
        self._name = None
        self._owner = None
    
    @property
    def name(self) -> str:
        """Extract repository name from URL."""
        if self._name is None:
            self._parse_url()
        return self._name
    
    @property
    def owner(self) -> str:
        """Extract repository owner from URL."""
        if self._owner is None:
            self._parse_url()
        return self._owner
    
    @property
    def full_name(self) -> str:
        """Return owner/repo format."""
        return f"{self.owner}/{self.name}"
    
    def _parse_url(self):
        """Parse owner and repo name from URL."""
        url = self.url
        
        # Handle different URL formats
        if url.startswith('https://github.com/'):
            parts = url.replace('https://github.com/', '').split('/')
        elif url.startswith('git@github.com:'):
            parts = url.replace('git@github.com:', '').replace('.git', '').split('/')
        else:
            parts = ['unknown', 'unknown']
        
        if len(parts) >= 2:
            self._owner = parts[0]
            self._name = parts[1].replace('.git', '')
        else:
            self._owner = 'unknown'
            self._name = 'unknown'