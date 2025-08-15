#!/usr/bin/env python3
"""Sentry.io API integration for error tracking analysis."""

import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs

import requests
import click


class SentryAnalyzer:
    """Analyzes Sentry error tracking data for projects."""
    
    def __init__(self, auth_token: Optional[str] = None, organization_slug: Optional[str] = None):
        """
        Initialize Sentry API client.
        
        Args:
            auth_token: Sentry API authentication token
            organization_slug: Sentry organization slug
        """
        self.auth_token = auth_token or os.getenv('SENTRY_AUTH_TOKEN')
        self.organization_slug = organization_slug or os.getenv('SENTRY_ORG_SLUG')
        self.base_url = "https://sentry.io/api/0"
        
        if not self.auth_token:
            click.echo("⚠️ Sentry analysis disabled: SENTRY_AUTH_TOKEN not provided")
            self.enabled = False
        else:
            self.enabled = True
            
        self.session = requests.Session()
        if self.auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            })
    
    def analyze_repository(self, repo_owner: str, repo_name: str) -> Dict[str, Any]:
        """
        Analyze Sentry error data for a given repository.
        
        Args:
            repo_owner: GitHub repository owner
            repo_name: GitHub repository name
            
        Returns:
            Dictionary containing Sentry analysis results
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'Sentry analysis disabled - no auth token provided',
                'issues': {
                    'past_month': {'total': 0, 'resolved': 0, 'unresolved': 0},
                    'events_count': 0,
                    'avg_resolution_time': {'days': 0, 'hours': 0}
                },
                'projects': []
            }
        
        try:
            # Find Sentry project(s) that match this repository
            projects = self._find_matching_projects(repo_owner, repo_name)
            
            if not projects:
                return {
                    'success': True,
                    'error': 'No matching Sentry projects found',
                    'issues': {
                        'past_month': {'total': 0, 'resolved': 0, 'unresolved': 0},
                        'events_count': 0,
                        'avg_resolution_time': {'days': 0, 'hours': 0}
                    },
                    'projects': []
                }
            
            # Aggregate data from all matching projects
            aggregated_data = {
                'success': True,
                'issues': {
                    'past_month': {'total': 0, 'resolved': 0, 'unresolved': 0},
                    'events_count': 0,
                    'avg_resolution_time': {'days': 0, 'hours': 0}
                },
                'projects': []
            }
            
            resolution_times = []
            
            for project in projects:
                project_data = self._analyze_project(project)
                if project_data['success']:
                    # Aggregate issue counts
                    for key in ['total', 'resolved', 'unresolved']:
                        aggregated_data['issues']['past_month'][key] += project_data['issues']['past_month'][key]
                    
                    aggregated_data['issues']['events_count'] += project_data['issues']['events_count']
                    
                    # Collect resolution times for averaging
                    if project_data['issues']['avg_resolution_time']['days'] > 0:
                        resolution_times.append(project_data['issues']['avg_resolution_time']['days'])
                    
                    aggregated_data['projects'].append({
                        'name': project['name'],
                        'slug': project['slug'],
                        'platform': project.get('platform', 'unknown'),
                        'issues': project_data['issues']
                    })
            
            # Calculate average resolution time across all projects
            if resolution_times:
                avg_days = sum(resolution_times) / len(resolution_times)
                aggregated_data['issues']['avg_resolution_time'] = {
                    'days': round(avg_days, 1),
                    'hours': round(avg_days * 24, 1)
                }
            
            return aggregated_data
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Sentry analysis failed: {str(e)}',
                'issues': {
                    'past_month': {'total': 0, 'resolved': 0, 'unresolved': 0},
                    'events_count': 0,
                    'avg_resolution_time': {'days': 0, 'hours': 0}
                },
                'projects': []
            }
    
    def _find_matching_projects(self, repo_owner: str, repo_name: str) -> List[Dict[str, Any]]:
        """
        Find Sentry projects that match a GitHub repository.
        
        Uses multiple strategies:
        1. Exact name match
        2. Repository name contained in project name
        3. Owner/organization match + similar name
        """
        if not self.organization_slug:
            # If no org slug, try to get all available projects
            projects = self._get_all_projects()
        else:
            projects = self._get_organization_projects(self.organization_slug)
        
        if not projects:
            return []
        
        matching_projects = []
        repo_name_lower = repo_name.lower()
        repo_owner_lower = repo_owner.lower()
        
        # Strategy 1: Exact name match
        for project in projects:
            project_name = project.get('name', '').lower()
            if project_name == repo_name_lower:
                matching_projects.append(project)
        
        # Strategy 2: Repository name contained in project name
        if not matching_projects:
            for project in projects:
                project_name = project.get('name', '').lower()
                if repo_name_lower in project_name or project_name in repo_name_lower:
                    matching_projects.append(project)
        
        # Strategy 3: Check project slug or team name contains repo info
        if not matching_projects:
            for project in projects:
                project_slug = project.get('slug', '').lower()
                team_name = project.get('team', {}).get('name', '').lower() if project.get('team') else ''
                
                if (repo_name_lower in project_slug or 
                    repo_owner_lower in project_slug or
                    repo_name_lower in team_name or
                    repo_owner_lower in team_name):
                    matching_projects.append(project)
        
        return matching_projects
    
    def _get_organization_projects(self, org_slug: str) -> List[Dict[str, Any]]:
        """Get all projects for a specific organization."""
        try:
            url = f"{self.base_url}/organizations/{org_slug}/projects/"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception:
            return []
    
    def _get_all_projects(self) -> List[Dict[str, Any]]:
        """Get all projects accessible to the user."""
        try:
            url = f"{self.base_url}/projects/"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception:
            return []
    
    def _analyze_project(self, project: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze error data for a specific Sentry project."""
        try:
            org_slug = project['organization']['slug']
            project_slug = project['slug']
            
            # Get issues from the past month
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            
            issues_data = self._get_project_issues(
                org_slug, 
                project_slug, 
                start_date, 
                end_date
            )
            
            events_data = self._get_project_events(
                org_slug,
                project_slug,
                start_date,
                end_date
            )
            
            # Calculate resolution statistics
            resolution_times = self._calculate_resolution_times(issues_data)
            
            return {
                'success': True,
                'issues': {
                    'past_month': {
                        'total': len(issues_data),
                        'resolved': len([i for i in issues_data if i.get('status') == 'resolved']),
                        'unresolved': len([i for i in issues_data if i.get('status') != 'resolved'])
                    },
                    'events_count': events_data.get('count', 0),
                    'avg_resolution_time': resolution_times
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'issues': {
                    'past_month': {'total': 0, 'resolved': 0, 'unresolved': 0},
                    'events_count': 0,
                    'avg_resolution_time': {'days': 0, 'hours': 0}
                }
            }
    
    def _get_project_issues(self, org_slug: str, project_slug: str, 
                           start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get issues for a project within a date range."""
        try:
            url = f"{self.base_url}/projects/{org_slug}/{project_slug}/issues/"
            params = {
                'query': f'firstSeen:>={start_date.isoformat()}',
                'statsPeriod': '30d',
                'limit': 100
            }
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
            
        except Exception:
            return []
    
    def _get_project_events(self, org_slug: str, project_slug: str,
                           start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get event statistics for a project."""
        try:
            url = f"{self.base_url}/projects/{org_slug}/{project_slug}/events/"
            params = {
                'statsPeriod': '30d',
                'full': 'false'
            }
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            events = response.json()
            
            return {
                'count': len(events) if isinstance(events, list) else 0,
                'events': events if isinstance(events, list) else []
            }
            
        except Exception:
            return {'count': 0, 'events': []}
    
    def _calculate_resolution_times(self, issues: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate average resolution time for resolved issues."""
        if not issues:
            return {'days': 0, 'hours': 0}
        
        resolution_times = []
        
        for issue in issues:
            if issue.get('status') == 'resolved':
                first_seen = issue.get('firstSeen')
                last_seen = issue.get('lastSeen')
                
                if first_seen and last_seen:
                    try:
                        # Parse ISO datetime strings
                        first_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                        last_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                        
                        # Calculate resolution time in days
                        resolution_time = (last_dt - first_dt).total_seconds() / (24 * 3600)
                        if resolution_time > 0:
                            resolution_times.append(resolution_time)
                    except Exception:
                        continue
        
        if not resolution_times:
            return {'days': 0, 'hours': 0}
        
        avg_days = sum(resolution_times) / len(resolution_times)
        return {
            'days': round(avg_days, 1),
            'hours': round(avg_days * 24, 1)
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Test Sentry API connection and return user/org information."""
        if not self.enabled:
            return {'success': False, 'error': 'No auth token provided'}
        
        try:
            # Test with user info endpoint
            url = f"{self.base_url}/user/"
            response = self.session.get(url)
            response.raise_for_status()
            user_data = response.json()
            
            # Get organizations
            orgs_url = f"{self.base_url}/organizations/"
            orgs_response = self.session.get(orgs_url)
            orgs_response.raise_for_status()
            orgs_data = orgs_response.json()
            
            return {
                'success': True,
                'user': user_data.get('name', user_data.get('email', 'Unknown')),
                'organizations': [org['slug'] for org in orgs_data],
                'total_projects': sum(org.get('projectCount', 0) for org in orgs_data)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Connection failed: {str(e)}'
            }