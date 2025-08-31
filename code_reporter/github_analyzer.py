"""GitHub API integration for repository statistics."""

import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .logger import get_logger


class GitHubAnalyzer:
    """Analyzes GitHub repositories using the gh CLI."""
    
    def __init__(self):
        # Verify gh CLI is available
        self._verify_gh_cli()
    
    def _verify_gh_cli(self):
        """Verify that gh CLI is available and authenticated."""
        try:
            result = subprocess.run(
                ['gh', 'auth', 'status'],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            if result.returncode != 0:
                logger = get_logger()
                logger.warning("gh CLI not authenticated. Some features may not work.")
        except FileNotFoundError:
            raise RuntimeError("gh CLI not found. Please install GitHub CLI.")
    
    def analyze_repository(self, owner: str, repo: str) -> Dict:
        """
        Analyze a GitHub repository for statistics.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Dictionary containing repository statistics
        """
        repo_full_name = f"{owner}/{repo}"
        
        result = {
            'repository': repo_full_name,
            'success': False,
            'error': None,
            'metadata': {},
            'issues': {},
            'commits': {},
            'contributors': {}
        }
        
        try:
            # Get repository metadata
            result['metadata'] = self._get_repository_metadata(owner, repo)
            
            # Get issue statistics (past month)
            result['issues'] = self._get_issue_statistics(owner, repo)
            
            # Get commit statistics (past month)
            result['commits'] = self._get_commit_statistics(owner, repo)
            
            # Get contributor information
            result['contributors'] = self._get_contributor_statistics(owner, repo)
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
            logger = get_logger()
            logger.warning(f"GitHub CLI/API error for {repo_full_name}: {str(e)}")
        
        return result
    
    def _get_repository_metadata(self, owner: str, repo: str) -> Dict:
        """Get basic repository metadata."""
        cmd = [
            'gh', 'repo', 'view', f"{owner}/{repo}",
            '--json', 'name,description,stargazerCount,forkCount,primaryLanguage,createdAt,pushedAt,isPrivate,licenseInfo'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        data = json.loads(result.stdout)
        
        return {
            'name': data.get('name'),
            'description': data.get('description'),
            'stars': data.get('stargazerCount', 0),
            'forks': data.get('forkCount', 0),
            'primary_language': data.get('primaryLanguage', {}).get('name') if data.get('primaryLanguage') else None,
            'created_at': data.get('createdAt'),
            'last_push': data.get('pushedAt'),
            'is_private': data.get('isPrivate', False),
            'license': data.get('licenseInfo', {}).get('name') if data.get('licenseInfo') else None
        }
    
    def _get_issue_statistics(self, owner: str, repo: str) -> Dict:
        """Get issue statistics for the past month."""
        one_month_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        # Get issues created in the past month
        cmd_created = [
            'gh', 'issue', 'list', 
            '--repo', f"{owner}/{repo}",
            '--state', 'all',
            '--search', f'created:>={one_month_ago}',
            '--json', 'number,state,createdAt,closedAt',
            '--limit', '1000'
        ]
        
        try:
            result = subprocess.run(cmd_created, capture_output=True, text=True, check=True, timeout=30)
            issues_data = json.loads(result.stdout)
            
            # Categorize issues
            total_issues = len(issues_data)
            closed_issues = len([issue for issue in issues_data if issue['state'] == 'closed'])
            open_issues = total_issues - closed_issues
            
            # Get issues closed in the past month (regardless of when they were created)
            cmd_closed = [
                'gh', 'issue', 'list',
                '--repo', f"{owner}/{repo}",
                '--state', 'closed',
                '--search', f'closed:>={one_month_ago}',
                '--json', 'number,closedAt,createdAt',
                '--limit', '1000'
            ]
            
            result_closed = subprocess.run(cmd_closed, capture_output=True, text=True, check=True, timeout=30)
            closed_data = json.loads(result_closed.stdout)
            resolved_count = len(closed_data)
            
            # Calculate average resolution time for issues closed in past month
            resolution_times = []
            for issue in closed_data:
                if issue.get('createdAt') and issue.get('closedAt'):
                    created = datetime.fromisoformat(issue['createdAt'].replace('Z', '+00:00'))
                    closed = datetime.fromisoformat(issue['closedAt'].replace('Z', '+00:00'))
                    resolution_time = (closed - created).total_seconds() / 3600  # Convert to hours
                    resolution_times.append(resolution_time)
            
            avg_resolution_hours = sum(resolution_times) / len(resolution_times) if resolution_times else 0
            avg_resolution_days = avg_resolution_hours / 24 if avg_resolution_hours > 0 else 0
            
            return {
                'past_month': {
                    'created': total_issues,
                    'resolved': resolved_count,
                    'still_open': open_issues
                },
                'resolution_rate': round(resolved_count / max(total_issues, 1) * 100, 1),
                'avg_resolution_time': {
                    'hours': round(avg_resolution_hours, 1),
                    'days': round(avg_resolution_days, 1)
                }
            }
            
        except subprocess.CalledProcessError as e:
            # Repository might not have issues enabled or accessible
            return {
                'past_month': {'created': 0, 'resolved': 0, 'still_open': 0},
                'resolution_rate': 0,
                'avg_resolution_time': {'hours': 0, 'days': 0},
                'error': 'Issues not accessible'
            }
    
    def _get_commit_statistics(self, owner: str, repo: str) -> Dict:
        """Get commit statistics for the past month."""
        one_month_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        cmd = [
            'gh', 'api',
            f"/repos/{owner}/{repo}/commits",
            '--method', 'GET',
            '--field', f'since={one_month_ago}T00:00:00Z',
            '--paginate',
            '--jq', '.[] | {sha: .sha, author: .commit.author.name, date: .commit.author.date, message: .commit.message}'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
            
            if not result.stdout.strip():
                return {
                    'past_month': {'total': 0, 'unique_authors': 0},
                    'top_contributors': []
                }
            
            # Parse commit data
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        commit_data = json.loads(line)
                        commits.append(commit_data)
                    except json.JSONDecodeError:
                        continue
            
            # Count authors
            authors = {}
            for commit in commits:
                author = commit.get('author', 'Unknown')
                authors[author] = authors.get(author, 0) + 1
            
            # Sort by commit count
            top_contributors = sorted(authors.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                'past_month': {
                    'total': len(commits),
                    'unique_authors': len(authors)
                },
                'top_contributors': [
                    {'name': name, 'commits': count} 
                    for name, count in top_contributors
                ]
            }
            
        except subprocess.CalledProcessError:
            return {
                'past_month': {'total': 0, 'unique_authors': 0},
                'top_contributors': [],
                'error': 'Commits not accessible'
            }
    
    def _get_contributor_statistics(self, owner: str, repo: str) -> Dict:
        """Get overall contributor statistics."""
        cmd = [
            'gh', 'api',
            f"/repos/{owner}/{repo}/contributors",
            '--method', 'GET',
            '--jq', '.[] | {login: .login, contributions: .contributions}'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
            
            if not result.stdout.strip():
                return {'total': 0, 'top_contributors': []}
            
            contributors = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        contributor_data = json.loads(line)
                        contributors.append(contributor_data)
                    except json.JSONDecodeError:
                        continue
            
            # Sort by contributions
            contributors.sort(key=lambda x: x.get('contributions', 0), reverse=True)
            
            return {
                'total': len(contributors),
                'top_contributors': contributors[:10]  # Top 10 contributors
            }
            
        except subprocess.CalledProcessError:
            return {
                'total': 0,
                'top_contributors': [],
                'error': 'Contributors not accessible'
            }
