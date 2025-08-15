"""LLM-powered analysis and summary generation."""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import litellm
import json
from jinja2 import Environment, FileSystemLoader


class LLMAnalyzer:
    """Uses LLMs to generate executive summaries and insights."""
    
    def __init__(self, model: str = None):
        if model:
            self.model = model
        else:
            self.model = self._select_model()
        
        # Set up Jinja2 environment for prompt templates
        self.template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=False  # We want raw text output for prompts
        )
        
        # Configure litellm
        litellm.set_verbose = False
    
    def _select_model(self) -> str:
        """Select the best available LLM model."""
        if os.getenv('ANTHROPIC_API_KEY'):
            return "claude-3-5-sonnet-20241022"
        elif os.getenv('OPENAI_API_KEY'):
            return "gpt-4o"
        else:
            raise ValueError("No LLM API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY")
    
    def generate_executive_summary(self, processed_data: Dict) -> str:
        """
        Generate an executive summary using LLM analysis.
        
        Args:
            processed_data: Processed analysis data from report generator
            
        Returns:
            Manager-friendly executive summary text
        """
        # Prepare context for the LLM
        context = self._prepare_llm_context(processed_data)
        
        # Load and render the prompt template
        try:
            template = self.jinja_env.get_template('llm_prompt.txt')
            prompt = template.render(
                context=context,
                context_json=json.dumps(context, indent=2)
            )
        except Exception as e:
            # Fallback to hardcoded prompt if template fails
            prompt = f"""You are a technical consultant writing an executive summary for senior management about their software portfolio. 

Based on the following analysis of {context['total_projects']} software projects, write a professional executive summary that:

1. Provides strategic insights about the technology portfolio
2. Highlights key risks and opportunities 
3. Makes actionable recommendations
4. Uses business-friendly language (avoid technical jargon)
5. Focuses on business impact and ROI implications

ANALYSIS DATA:
{json.dumps(context, indent=2)}

Write a comprehensive executive summary in 3-4 paragraphs that tells the story of this software portfolio from a business perspective. Focus on:
- Portfolio health and maturity
- Security posture and business risk
- Development velocity and team effectiveness  
- Strategic technology choices
- Immediate actions needed

Keep it executive-level: strategic, actionable, and focused on business outcomes."""

        try:
            response = litellm.completion(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            # Fallback to a basic summary if LLM fails
            return self._generate_fallback_summary(context)
    
    def generate_project_summary(self, project_data: Dict) -> str:
        """
        Generate a brief project description using LLM.
        
        Args:
            project_data: Individual project analysis data
            
        Returns:
            Brief project summary
        """
        if not project_data.get('github_metadata', {}).get('description'):
            return "No description available."
        
        description = project_data['github_metadata']['description']
        language = project_data.get('primary_language', 'Unknown')
        stars = project_data.get('github_metadata', {}).get('stars', 0)
        
        prompt = f"""Summarize this software project for a business audience in 1-2 sentences:

Project: {project_data['name']}
Description: {description}
Technology: {language}
Popularity: {stars} GitHub stars

Write a concise business-focused summary that explains what this project does and why it matters."""

        try:
            response = litellm.completion(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception:
            return description
    
    def _prepare_llm_context(self, processed_data: Dict) -> Dict:
        """Prepare structured context data for LLM analysis."""
        summary = processed_data['summary']
        projects = processed_data['projects']
        
        # Calculate additional insights
        high_activity_projects = []
        vulnerable_projects = []
        popular_projects = []
        
        for project in projects.values():
            if not project.get('success'):
                continue
                
            # High activity (significant commits)
            commits = project.get('github_commits', {}).get('past_month', {}).get('total', 0)
            if commits >= 10:
                high_activity_projects.append({
                    'name': project['name'],
                    'commits': commits,
                    'contributors': project.get('github_commits', {}).get('past_month', {}).get('unique_authors', 0)
                })
            
            # Vulnerable projects
            vuln_count = project.get('vulnerability_summary', {}).get('vulnerable_packages', 0)
            if vuln_count > 0:
                vulnerable_projects.append({
                    'name': project['name'],
                    'vulnerabilities': vuln_count,
                    'critical_issues': len([v for v in project.get('vulnerabilities', []) 
                                          if 'high' in str(v.get('vulnerability', {}).get('severity', '')).lower()])
                })
            
            # Popular projects (high stars)
            stars = project.get('github_metadata', {}).get('stars', 0)
            if stars >= 1000:
                popular_projects.append({
                    'name': project['name'],
                    'stars': stars,
                    'language': project.get('primary_language')
                })
        
        context = {
            'total_projects': summary['successful_analyses'],
            'languages': dict(summary['languages']),
            'frameworks': dict(summary['frameworks']),
            'licenses': dict(summary['license_distribution']),
            'security_metrics': {
                'total_vulnerabilities': summary['total_vulnerabilities'],
                'vulnerable_projects': len(vulnerable_projects),
                'vulnerable_project_details': vulnerable_projects,
                'risk_percentage': round((len(vulnerable_projects) / max(summary['successful_analyses'], 1)) * 100, 1)
            },
            'activity_metrics': {
                'total_commits_month': summary['activity_metrics']['total_commits'],
                'total_contributors': summary['activity_metrics']['total_contributors'],
                'high_activity_projects': high_activity_projects,
                'average_commits_per_project': round(summary['activity_metrics']['total_commits'] / max(summary['successful_analyses'], 1), 1)
            },
            'popularity_metrics': {
                'total_stars': summary['activity_metrics']['total_stars'],
                'total_forks': summary['activity_metrics']['total_forks'],
                'popular_projects': sorted(popular_projects, key=lambda x: x['stars'], reverse=True)[:3]
            },
            'technology_insights': {
                'primary_languages': list(summary['languages'].keys()),
                'framework_diversity': len(summary['frameworks']),
                'license_compliance': len(summary['license_distribution']) > 0
            },
            'total_dependencies': summary['total_dependencies']
        }
        
        return context
    
    def _generate_fallback_summary(self, context: Dict) -> str:
        """Generate a basic summary if LLM is unavailable."""
        total_projects = context['total_projects']
        vuln_projects = context['security_metrics']['vulnerable_projects']
        risk_pct = context['security_metrics']['risk_percentage']
        
        summary = f"""This analysis covers {total_projects} software projects representing your organization's technology portfolio. """
        
        if vuln_projects > 0:
            summary += f"Security assessment reveals {vuln_projects} projects ({risk_pct}%) with known vulnerabilities requiring immediate attention. "
        else:
            summary += "Security posture is strong with no known vulnerabilities detected across the portfolio. "
        
        summary += f"Development activity shows {context['activity_metrics']['total_commits_month']} commits in the past month, "
        summary += f"indicating {'active' if context['activity_metrics']['total_commits_month'] > 20 else 'moderate'} ongoing development. "
        
        if context['popularity_metrics']['popular_projects']:
            summary += f"The portfolio includes high-value assets with significant community adoption, "
            summary += f"totaling {context['popularity_metrics']['total_stars']} GitHub stars across all projects."
        
        return summary