"""HTML report generation functionality."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from jinja2 import Environment, FileSystemLoader, Template
import pandas as pd
import markdown
from .llm_analyzer import LLMAnalyzer
from .logger import get_logger


class ReportGenerator:
    """Generates HTML reports from analysis results."""
    
    def __init__(self, output_dir: Path, llm_model: str = "openai/o4-mini"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize LLM analyzer
        try:
            self.llm_analyzer = LLMAnalyzer(model=llm_model)
        except ValueError as e:
            logger = get_logger()
            logger.warning(f"LLM analyzer unavailable: {e}")
            self.llm_analyzer = None
        
        # Set up Jinja2 environment
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        
        # Add custom markdown filter
        def markdown_filter(text):
            """Convert markdown text to HTML."""
            if not text:
                return ""
            # Initialize markdown with common extensions
            md = markdown.Markdown(extensions=['extra', 'nl2br'])
            return md.convert(text)
        
        self.jinja_env.filters['markdown'] = markdown_filter
        
        # Create templates if they don't exist
        self._ensure_templates()
    
    def generate_reports(self, analysis_results: Dict, format_type: str = 'html') -> Dict:
        """
        Generate reports from analysis results.
        
        Args:
            analysis_results: Dictionary of analysis results per repository
            format_type: 'html', 'pdf', or 'both'
            
        Returns:
            Dictionary with paths to generated reports
        """
        report_paths = {}
        
        # Process data for reporting
        processed_data = self._process_analysis_data(analysis_results)
        
        # Generate individual project reports
        for repo_url, data in processed_data['projects'].items():
            if data.get('success'):
                # Generate LLM summary for this project
                if self.llm_analyzer:
                    try:
                        logger = get_logger()
                        logger.debug(f"Generating project summary for {data['name']}")
                        data['llm_project_summary'] = self.llm_analyzer.generate_project_summary(data)
                        logger.debug(f"Project summary generated: {len(data.get('llm_project_summary', ''))} characters")
                    except Exception as e:
                        logger = get_logger()
                        logger.warning(f"Project summary generation failed for {data['name']}: {e}")
                        data['llm_project_summary'] = None
                else:
                    logger = get_logger()
                    logger.debug("LLM analyzer not available for project summaries")
                    data['llm_project_summary'] = None
                    
                project_html = self._generate_project_report(data)
                project_filename = self._sanitize_filename(f"{data['name']}_report.html")
                project_path = self.output_dir / project_filename
                
                with open(project_path, 'w', encoding='utf-8') as f:
                    f.write(project_html)
                
                report_paths[repo_url] = str(project_path)
        
        # Generate executive summary
        summary_html = self._generate_executive_summary(processed_data)
        summary_path = self.output_dir / "executive_summary.html"
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary_html)
        
        report_paths['executive_summary'] = str(summary_path)
        
        # Generate combined report (all projects in one document)
        combined_html = self._generate_combined_report(processed_data)
        combined_path = self.output_dir / "combined_report.html"
        
        with open(combined_path, 'w', encoding='utf-8') as f:
            f.write(combined_html)
        
        report_paths['combined_report'] = str(combined_path)
        
        return report_paths
    
    def _process_analysis_data(self, analysis_results: Dict) -> Dict:
        """Process raw analysis results into structured data for reporting."""
        processed = {
            'generated_at': datetime.now().isoformat(),
            'projects': {},
            'summary': {
                'total_projects': len(analysis_results),
                'successful_analyses': 0,
                'failed_analyses': 0,
                'total_dependencies': 0,
                'unique_dependencies': set(),
                'total_vulnerabilities': 0,
                'languages': {},
                'frameworks': {},
                'license_distribution': {},
                'dependency_license_distribution': {},
                'activity_metrics': {
                    'total_commits': 0,
                    'total_contributors': 0,
                    'total_stars': 0,
                    'total_forks': 0
                },
                'sentry_metrics': {
                    'projects_with_sentry': 0,
                    'total_sentry_issues': 0,
                    'total_sentry_resolved': 0,
                    'total_sentry_events': 0,
                    'avg_resolution_time': 0.0,
                    'projects_with_errors': 0
                }
            },
            'charts': {}
        }
        
        for repo_url, result in analysis_results.items():
            if not result.get('success'):
                processed['summary']['failed_analyses'] += 1
                continue
            
            processed['summary']['successful_analyses'] += 1
            
            # Extract project data
            repo_info = result['repo_info']
            language_info = result['language_info']
            github_stats = result.get('github_stats', {})
            dependency_info = result.get('dependency_info', {})
            sentry_stats = result.get('sentry_stats', {})
            
            project_data = {
                'success': True,
                'name': repo_info.name,
                'owner': repo_info.owner,
                'full_name': repo_info.full_name,
                'url': repo_url,
                'primary_language': language_info.get('primary_language'),
                'language_details': language_info.get('languages', {}),
                'github_metadata': github_stats.get('metadata', {}),
                'github_issues': github_stats.get('issues', {}),
                'github_commits': github_stats.get('commits', {}),
                'dependencies': dependency_info.get('dependencies', {}),
                'vulnerability_summary': dependency_info.get('summary', {}),
                'vulnerabilities': dependency_info.get('vulnerabilities', []),
                'dependency_licenses': dependency_info.get('licenses', {}),
                'sentry_issues': sentry_stats.get('issues', {}),
                'sentry_projects': sentry_stats.get('projects', []),
                'sentry_enabled': sentry_stats.get('success', False)
            }
            
            processed['projects'][repo_url] = project_data
            
            # Aggregate summary data
            self._update_summary_metrics(processed['summary'], project_data)
        
        # Convert unique dependencies set to count
        processed['summary']['unique_dependency_count'] = len(processed['summary']['unique_dependencies'])
        
        # Generate chart data
        processed['charts'] = self._generate_charts(processed)
        
        # Generate LLM-powered executive summary
        if self.llm_analyzer:
            try:
                logger = get_logger()
                logger.debug("Calling LLM for executive summary")
                processed['llm_summary'] = self.llm_analyzer.generate_executive_summary(processed)
                logger.debug(f"LLM summary generated: {len(processed.get('llm_summary', ''))} characters")
            except Exception as e:
                logger = get_logger()
                logger.warning(f"LLM summary generation failed: {e}")
                processed['llm_summary'] = None
        else:
            logger = get_logger()
            logger.debug("LLM analyzer not available")
            processed['llm_summary'] = None
        
        return processed
    
    def _update_summary_metrics(self, summary: Dict, project_data: Dict):
        """Update summary metrics with project data."""
        # Language distribution
        primary_lang = project_data.get('primary_language')
        if primary_lang:
            summary['languages'][primary_lang] = summary['languages'].get(primary_lang, 0) + 1
        
        # Framework distribution
        for lang, lang_data in project_data.get('language_details', {}).items():
            for framework in lang_data.get('frameworks', {}):
                summary['frameworks'][framework] = summary['frameworks'].get(framework, 0) + 1
        
        # License distribution
        license_name = project_data.get('github_metadata', {}).get('license')
        if license_name:
            summary['license_distribution'][license_name] = summary['license_distribution'].get(license_name, 0) + 1
        
        # Activity metrics
        metadata = project_data.get('github_metadata', {})
        commits = project_data.get('github_commits', {}).get('past_month', {})
        
        summary['activity_metrics']['total_stars'] += metadata.get('stars', 0)
        summary['activity_metrics']['total_forks'] += metadata.get('forks', 0)
        summary['activity_metrics']['total_commits'] += commits.get('total', 0)
        summary['activity_metrics']['total_contributors'] += commits.get('unique_authors', 0)
        
        # Dependency and security metrics
        vuln_summary = project_data.get('vulnerability_summary', {})
        summary['total_dependencies'] += vuln_summary.get('total_dependencies', 0)
        summary['total_vulnerabilities'] += vuln_summary.get('vulnerable_packages', 0)
        
        # Track unique dependencies (simple deduplication)
        dependencies = project_data.get('dependencies', {})
        for language, dep_categories in dependencies.items():
            if isinstance(dep_categories, dict):
                for category, packages in dep_categories.items():
                    if isinstance(packages, dict):
                        for package_name in packages.keys():
                            dep_key = f"{language}:{package_name}"
                            summary['unique_dependencies'].add(dep_key)
        
        # Aggregate dependency license distribution
        dep_licenses = project_data.get('dependency_licenses', {})
        for license_name, count in dep_licenses.items():
            summary['dependency_license_distribution'][license_name] = summary['dependency_license_distribution'].get(license_name, 0) + count
        
        # Sentry metrics
        if project_data.get('sentry_enabled'):
            summary['sentry_metrics']['projects_with_sentry'] += 1
            
            sentry_issues = project_data.get('sentry_issues', {})
            past_month = sentry_issues.get('past_month', {})
            
            issues_total = past_month.get('total', 0)
            issues_resolved = past_month.get('resolved', 0)
            events_count = sentry_issues.get('events_count', 0)
            
            summary['sentry_metrics']['total_sentry_issues'] += issues_total
            summary['sentry_metrics']['total_sentry_resolved'] += issues_resolved
            summary['sentry_metrics']['total_sentry_events'] += events_count
            
            if issues_total > 0:
                summary['sentry_metrics']['projects_with_errors'] += 1
            
            # Track resolution times for averaging
            resolution_time = sentry_issues.get('avg_resolution_time', {}).get('days', 0)
            if resolution_time > 0:
                # This is a simple average - could be improved with weighted averaging
                current_avg = summary['sentry_metrics']['avg_resolution_time']
                projects_count = summary['sentry_metrics']['projects_with_sentry']
                summary['sentry_metrics']['avg_resolution_time'] = (
                    (current_avg * (projects_count - 1) + resolution_time) / projects_count
                )
    
    def _generate_charts(self, processed_data: Dict) -> Dict:
        """Generate chart data for the reports."""
        charts = {}
        summary = processed_data['summary']
        
        # Language distribution pie chart
        if summary['languages']:
            fig_lang = px.pie(
                values=list(summary['languages'].values()),
                names=list(summary['languages'].keys()),
                title="Primary Languages Distribution"
            )
            charts['language_distribution'] = fig_lang.to_html(include_plotlyjs=False, div_id="lang-chart")
        
        # Dependency license distribution pie chart (executive summary)
        if summary['dependency_license_distribution']:
            logger = get_logger()
            logger.debug(f"Executive summary chart data: {summary['dependency_license_distribution']}")
            # Ensure values are proper native Python integers for Plotly
            exec_chart_values = [int(v) if v is not None else 0 for v in summary['dependency_license_distribution'].values()]
            exec_chart_names = list(summary['dependency_license_distribution'].keys())
            # Force to native Python types to avoid numpy encoding issues
            exec_chart_values = [int(x) for x in exec_chart_values]
            logger.debug(f"Executive chart values: {exec_chart_values}, names: {exec_chart_names}")
            
            # Create DataFrame explicitly to avoid encoding issues
            import pandas as pd
            exec_df = pd.DataFrame({
                'license': exec_chart_names,
                'count': exec_chart_values
            })
            
            # Use graph_objects for explicit control over data types
            fig_dep_licenses = go.Figure(data=[go.Pie(
                labels=exec_chart_names,
                values=exec_chart_values,
                textinfo='label+percent',
                hovertemplate='<b>%{label}</b><br>Dependencies: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            fig_dep_licenses.update_layout(title_text="Dependency License Distribution")
            charts['dependency_license_distribution'] = fig_dep_licenses.to_html(include_plotlyjs=False, div_id="dep-license-chart")
        
        # Security overview chart
        vuln_projects = sum(1 for p in processed_data['projects'].values() 
                           if p.get('vulnerability_summary', {}).get('vulnerable_packages', 0) > 0)
        safe_projects = summary['successful_analyses'] - vuln_projects
        
        fig_security = go.Figure(data=[
            go.Bar(x=['Projects with Vulnerabilities', 'Secure Projects'], 
                   y=[vuln_projects, safe_projects],
                   marker_color=['red', 'green'])
        ])
        fig_security.update_layout(title="Security Overview")
        charts['security_overview'] = fig_security.to_html(include_plotlyjs=False, div_id="security-chart")
        
        # Issue resolution metrics chart
        projects = list(processed_data['projects'].values())
        if projects:
            project_names = [p['name'] for p in projects]
            issues_created = [p.get('github_issues', {}).get('past_month', {}).get('created', 0) for p in projects]
            issues_resolved = [p.get('github_issues', {}).get('past_month', {}).get('resolved', 0) for p in projects]
            avg_resolution_days = [p.get('github_issues', {}).get('avg_resolution_time', {}).get('days', 0) for p in projects]
            
            fig_activity = make_subplots(
                rows=1, cols=2, 
                subplot_titles=('Issue Management (Past 30 Days)', 'Average Resolution Time (Days)'),
                specs=[[{"secondary_y": False}, {"secondary_y": False}]]
            )
            
            # Issues created vs resolved
            fig_activity.add_trace(
                go.Bar(x=project_names, y=issues_created, name="Issues Created", marker_color='lightblue'),
                row=1, col=1
            )
            fig_activity.add_trace(
                go.Bar(x=project_names, y=issues_resolved, name="Issues Resolved", marker_color='green'),
                row=1, col=1
            )
            
            # Average resolution time
            fig_activity.add_trace(
                go.Bar(x=project_names, y=avg_resolution_days, name="Avg Resolution Time", marker_color='orange'),
                row=1, col=2
            )
            
            fig_activity.update_layout(title_text="Issue Resolution Metrics")
            charts['activity_metrics'] = fig_activity.to_html(include_plotlyjs=False, div_id="activity-chart")
        
        return charts
    
    def _generate_project_report(self, project_data: Dict) -> str:
        """Generate HTML report for a single project."""
        template = self.jinja_env.get_template('project_report.html')
        
        # Generate dependency license chart for this project
        project_dep_license_chart = None
        dep_licenses = project_data.get('dependency_licenses', {})
        if dep_licenses:
            logger = get_logger()
            logger.debug(f"Chart data for {project_data['name']}: {dep_licenses}")
            # Ensure values are proper native Python integers for Plotly
            chart_values = [int(v) if v is not None else 0 for v in dep_licenses.values()]
            chart_names = list(dep_licenses.keys())
            # Force to native Python types to avoid numpy encoding issues
            chart_values = [int(x) for x in chart_values]
            logger.debug(f"Chart values: {chart_values}, names: {chart_names}")
            
            # Create DataFrame explicitly to avoid encoding issues
            import pandas as pd
            df = pd.DataFrame({
                'license': chart_names,
                'count': chart_values
            })
            
            # Use graph_objects for explicit control over data types
            fig_project_dep_licenses = go.Figure(data=[go.Pie(
                labels=chart_names,
                values=chart_values,
                textinfo='label+percent',
                hovertemplate='<b>%{label}</b><br>Dependencies: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            fig_project_dep_licenses.update_layout(title_text="Dependency License Distribution")
            project_dep_license_chart = fig_project_dep_licenses.to_html(include_plotlyjs=False, div_id=f"project-dep-license-chart-{project_data['name']}")
        
        # Prepare template data
        template_data = {
            'project': project_data,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'has_vulnerabilities': len(project_data.get('vulnerabilities', [])) > 0,
            'vulnerability_count': len(project_data.get('vulnerabilities', [])),
            'dependency_count': project_data.get('vulnerability_summary', {}).get('total_dependencies', 0),
            'dependency_license_chart': project_dep_license_chart
        }
        
        return template.render(**template_data)
    
    def _generate_executive_summary(self, processed_data: Dict) -> str:
        """Generate executive summary HTML report."""
        template = self.jinja_env.get_template('executive_summary.html')
        
        # Prepare summary data
        summary = processed_data['summary']
        charts = processed_data['charts']
        
        # Calculate risk metrics
        total_projects = summary['successful_analyses']
        vulnerable_projects = sum(1 for p in processed_data['projects'].values() 
                                if p.get('vulnerability_summary', {}).get('vulnerable_packages', 0) > 0)
        
        risk_score = (vulnerable_projects / max(total_projects, 1)) * 100
        
        template_data = {
            'summary': summary,
            'charts': charts,
            'projects': list(processed_data['projects'].values()),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'llm_summary': processed_data.get('llm_summary'),
            'risk_metrics': {
                'vulnerable_projects': vulnerable_projects,
                'risk_score': round(risk_score, 1),
                'total_vulnerabilities': summary['total_vulnerabilities']
            }
        }
        
        return template.render(**template_data)
    
    def _generate_combined_report(self, processed_data: Dict) -> str:
        """Generate combined report HTML with all projects in one document."""
        template = self.jinja_env.get_template('combined_report.html')
        
        # Prepare summary data (same as executive summary)
        summary = processed_data['summary']
        charts = processed_data['charts']
        
        # Calculate risk metrics
        total_projects = summary['successful_analyses']
        vulnerable_projects = sum(1 for p in processed_data['projects'].values() 
                                if p.get('vulnerability_summary', {}).get('vulnerable_packages', 0) > 0)
        
        risk_score = (vulnerable_projects / max(total_projects, 1)) * 100
        
        # Enhance each project with template-specific variables for consistency with individual project reports
        enhanced_projects = {}
        logger = get_logger()
        
        for repo_url, project_data in processed_data['projects'].items():
            if project_data.get('success'):
                # Generate dependency license chart for this project (same logic as individual project reports)
                project_dep_license_chart = None
                dep_licenses = project_data.get('dependency_licenses', {})
                if dep_licenses:
                    logger.debug(f"Chart data for {project_data['name']}: {dep_licenses}")
                    # Ensure values are proper native Python integers for Plotly
                    chart_values = [int(v) if v is not None else 0 for v in dep_licenses.values()]
                    chart_names = list(dep_licenses.keys())
                    # Force to native Python types to avoid numpy encoding issues
                    chart_values = [int(x) for x in chart_values]
                    logger.debug(f"Chart values: {chart_values}, names: {chart_names}")
                    
                    # Use graph_objects for explicit control over data types
                    fig_project_dep_licenses = go.Figure(data=[go.Pie(
                        labels=chart_names,
                        values=chart_values,
                        textinfo='label+percent',
                        hovertemplate='<b>%{label}</b><br>Dependencies: %{value}<br>Percentage: %{percent}<extra></extra>'
                    )])
                    fig_project_dep_licenses.update_layout(title_text="Dependency License Distribution")
                    project_dep_license_chart = fig_project_dep_licenses.to_html(include_plotlyjs=False, div_id=f"combined-project-dep-license-chart-{project_data['name']}")
                
                # Create enhanced project data with template variables
                enhanced_project = dict(project_data)
                enhanced_project.update({
                    'dependency_license_chart': project_dep_license_chart,
                    'has_vulnerabilities': len(project_data.get('vulnerabilities', [])) > 0,
                    'vulnerability_count': len(project_data.get('vulnerabilities', [])),
                    'dependency_count': project_data.get('vulnerability_summary', {}).get('total_dependencies', 0)
                })
                enhanced_projects[repo_url] = enhanced_project
            else:
                enhanced_projects[repo_url] = project_data
        
        template_data = {
            'summary': summary,
            'charts': charts,
            'projects': enhanced_projects,  # Dictionary for individual project sections
            'projects_list': list(enhanced_projects.values()),  # List for executive summary section
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'llm_summary': processed_data.get('llm_summary'),
            'risk_metrics': {
                'vulnerable_projects': vulnerable_projects,
                'risk_score': round(risk_score, 1),
                'total_vulnerabilities': summary['total_vulnerabilities']
            }
        }
        
        return template.render(**template_data)
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for filesystem compatibility."""
        import re
        # Remove or replace invalid characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        return sanitized.replace(' ', '_')
    
    def _ensure_templates(self):
        """Create HTML templates if they don't exist."""
        # Create project report template
        project_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ project.name }} - Code Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007acc; margin: 0; font-size: 2.5em; }
        .header .meta { color: #666; margin-top: 10px; }
        .section { margin: 30px 0; }
        .section h2 { color: #333; border-left: 4px solid #007acc; padding-left: 15px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: #f9f9f9; padding: 20px; border-radius: 6px; border-left: 4px solid #007acc; }
        .vulnerability { background: #fff5f5; border-left-color: #dc3545; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .vulnerability.high { background: #fff0f0; border-left-color: #dc3545; }
        .vulnerability.medium { background: #fff8f0; border-left-color: #fd7e14; }
        .vulnerability.low { background: #f0f8f0; border-left-color: #28a745; }
        .secure { color: #28a745; font-weight: bold; }
        .warning { color: #dc3545; font-weight: bold; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge.success { background: #d4edda; color: #155724; }
        .badge.danger { background: #f8d7da; color: #721c24; }
        .badge.warning { background: #fff3cd; color: #856404; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-item { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 6px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007acc; }
        .executive-summary { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #007acc; }
        .llm-summary { line-height: 1.6; }
        .llm-summary p { margin: 0 0 15px 0; text-align: justify; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ project.name }}</h1>
            <div class="meta">
                <strong>Owner:</strong> {{ project.owner }} | 
                <strong>URL:</strong> <a href="{{ project.url }}" target="_blank">{{ project.url }}</a> |
                <strong>Generated:</strong> {{ generated_at }}
            </div>
        </div>

        <!-- Executive Summary -->
        {% if project.llm_project_summary %}
        <div class="section">
            <div class="executive-summary">
                <h2>📋 Executive Summary</h2>
                <div class="llm-summary">
                    {{ project.llm_project_summary | markdown | safe }}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Overview Section -->
        <div class="section">
            <h2>📊 Project Overview</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-number">{{ project.github_metadata.stars | default(0) }}</div>
                    <div>Stars</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{{ project.github_metadata.forks | default(0) }}</div>
                    <div>Forks</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{{ dependency_count }}</div>
                    <div>Dependencies</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number {% if vulnerability_count > 0 %}warning{% else %}secure{% endif %}">{{ vulnerability_count }}</div>
                    <div>Vulnerabilities</div>
                </div>
            </div>
        </div>

        <!-- Technology Stack -->
        <div class="section">
            <h2>🔧 Technology Stack</h2>
            <div class="grid">
                <div class="card">
                    <h3>Primary Language</h3>
                    <p><strong>{{ project.primary_language | title }}</strong></p>
                    {% if project.language_details[project.primary_language] %}
                        {% set lang_data = project.language_details[project.primary_language] %}
                        {% if lang_data.version %}
                            <p>Version: {{ lang_data.version }}</p>
                        {% endif %}
                        {% if lang_data.frameworks %}
                            <p><strong>Frameworks:</strong></p>
                            <ul>
                            {% for framework, info in lang_data.frameworks.items() %}
                                <li>{{ framework | title }} 
                                    {% if info.version != 'unknown' %}(v{{ info.version }}){% endif %}
                                </li>
                            {% endfor %}
                            </ul>
                        {% endif %}
                    {% endif %}
                </div>
                <div class="card">
                    <h3>Repository Info</h3>
                    {% if project.github_metadata.license %}
                        <p><strong>License:</strong> {{ project.github_metadata.license }}</p>
                    {% endif %}
                    {% if project.github_metadata.description %}
                        <p><strong>Description:</strong> {{ project.github_metadata.description }}</p>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- Security Analysis -->
        <div class="section">
            <h2>🛡️ Security Analysis</h2>
            {% if has_vulnerabilities %}
                <p class="warning">⚠️ {{ vulnerability_count }} security vulnerabilities found</p>
                {% for vuln in project.vulnerabilities[:10] %}
                    <div class="vulnerability">
                        <h4>{{ vuln.package }} v{{ vuln.version }}</h4>
                        <p>{{ vuln.vulnerability.summary }}</p>
                        <p><strong>Severity:</strong> <span class="badge {% if 'high' in vuln.vulnerability.severity.lower() %}danger{% elif 'medium' in vuln.vulnerability.severity.lower() %}warning{% else %}success{% endif %}">{{ vuln.vulnerability.severity }}</span></p>
                        {% if vuln.vulnerability.id %}
                            <p><strong>ID:</strong> {{ vuln.vulnerability.id }}</p>
                        {% endif %}
                    </div>
                {% endfor %}
            {% else %}
                <p class="secure">✅ No known security vulnerabilities found</p>
            {% endif %}
        </div>

        <!-- Activity Metrics -->
        <div class="section">
            <h2>📈 Recent Activity (Past 30 Days)</h2>
            <div class="grid">
                <div class="card">
                    <h3>Development Activity</h3>
                    <p><strong>Commits:</strong> {{ project.github_commits.past_month.total | default(0) }}</p>
                    <p><strong>Contributors:</strong> {{ project.github_commits.past_month.unique_authors | default(0) }}</p>
                    {% if project.github_commits.top_contributors %}
                        <p><strong>Top Contributor:</strong> {{ project.github_commits.top_contributors[0].name }} ({{ project.github_commits.top_contributors[0].commits }} commits)</p>
                    {% endif %}
                </div>
                <div class="card">
                    <h3>Issue Management</h3>
                    <p><strong>Issues Created:</strong> {{ project.github_issues.past_month.created | default(0) }}</p>
                    <p><strong>Issues Resolved:</strong> {{ project.github_issues.past_month.resolved | default(0) }}</p>
                    <p><strong>Resolution Rate:</strong> {{ project.github_issues.resolution_rate | default(0) }}%</p>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Code Reporter on {{ generated_at }}</p>
        </div>
    </div>
</body>
</html>'''

        # Create executive summary template
        executive_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - Code Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 30px; margin-bottom: 40px; }
        .header h1 { color: #007acc; margin: 0; font-size: 3em; }
        .header .subtitle { color: #666; font-size: 1.2em; margin-top: 10px; }
        .executive-summary { background: #f8f9fa; padding: 30px; border-radius: 8px; margin: 30px 0; border-left: 5px solid #007acc; }
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .kpi-card { background: linear-gradient(135deg, #007acc, #0056b3); color: white; padding: 30px; border-radius: 8px; text-align: center; }
        .kpi-card h3 { margin: 0; font-size: 2.5em; }
        .kpi-card p { margin: 10px 0 0 0; font-size: 1.1em; opacity: 0.9; }
        .risk-card { background: linear-gradient(135deg, #dc3545, #b02a37); }
        .success-card { background: linear-gradient(135deg, #28a745, #1e7e34); }
        .warning-card { background: linear-gradient(135deg, #fd7e14, #e55100); }
        .section { margin: 40px 0; }
        .section h2 { color: #333; border-left: 4px solid #007acc; padding-left: 15px; font-size: 1.8em; }
        .chart-container { background: white; padding: 20px; border-radius: 6px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .project-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .project-card { background: #f9f9f9; padding: 20px; border-radius: 6px; border-left: 4px solid #007acc; }
        .project-card.vulnerable { border-left-color: #dc3545; }
        .project-card h4 { margin-top: 0; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 15px; font-size: 0.85em; font-weight: bold; }
        .badge.success { background: #d4edda; color: #155724; }
        .badge.danger { background: #f8d7da; color: #721c24; }
        .badge.warning { background: #fff3cd; color: #856404; }
        .footer { margin-top: 50px; padding-top: 30px; border-top: 1px solid #eee; color: #666; text-align: center; }
        .recommendations { background: #fff8f0; border: 1px solid #fd7e14; border-radius: 8px; padding: 25px; margin: 30px 0; }
        .recommendations h3 { color: #fd7e14; margin-top: 0; }
        .llm-summary { line-height: 1.6; }
        .llm-summary p { margin: 0 0 15px 0; text-align: justify; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Executive Summary</h1>
            <div class="subtitle">Code Repository Analysis Report</div>
            <div class="subtitle">Generated on {{ generated_at }}</div>
        </div>

        <!-- Key Performance Indicators -->
        <div class="section">
            <div class="kpi-grid">
                <div class="kpi-card">
                    <h3>{{ summary.successful_analyses }}</h3>
                    <p>Projects Analyzed</p>
                </div>
                <div class="kpi-card success-card">
                    <h3>{{ summary.total_dependencies }}</h3>
                    <p>Total Dependencies</p>
                </div>
                <div class="kpi-card {% if risk_metrics.vulnerable_projects > 0 %}risk-card{% else %}success-card{% endif %}">
                    <h3>{{ risk_metrics.vulnerable_projects }}</h3>
                    <p>Projects with Vulnerabilities</p>
                </div>
                <div class="kpi-card warning-card">
                    <h3>{{ risk_metrics.risk_score }}%</h3>
                    <p>Security Risk Score</p>
                </div>
            </div>
        </div>

        <!-- Executive Summary Text -->
        <div class="executive-summary">
            <h2>📋 Executive Analysis</h2>
            {% if llm_summary %}
                <!-- LLM-Generated Strategic Summary -->
                <div class="llm-summary">
                    <p>{{ llm_summary | replace('\n\n', '</p><p>') | safe }}</p>
                </div>
            {% else %}
                <!-- Fallback Summary -->
                <p>This report analyzes <strong>{{ summary.successful_analyses }} software projects</strong> across multiple programming languages and frameworks. The analysis covers code quality, security vulnerabilities, dependency management, and development activity metrics.</p>
                
                {% if risk_metrics.vulnerable_projects > 0 %}
                    <p><strong>⚠️ Security Alert:</strong> {{ risk_metrics.vulnerable_projects }} out of {{ summary.successful_analyses }} projects have known security vulnerabilities, representing a {{ risk_metrics.risk_score }}% risk exposure. Immediate attention is recommended for vulnerable projects.</p>
                {% else %}
                    <p><strong>✅ Security Status:</strong> All analyzed projects show clean security profiles with no known vulnerabilities detected.</p>
                {% endif %}

                <p><strong>Technology Stack:</strong> The portfolio spans {{ summary.languages|length }} primary programming languages with {{ summary.frameworks|length }} different frameworks in use.</p>
                
                <p><strong>Development Activity:</strong> Across all projects, there have been {{ summary.activity_metrics.total_commits }} commits in the past month by {{ summary.activity_metrics.total_contributors }} unique contributors, indicating {{ "active" if summary.activity_metrics.total_commits > 10 else "moderate" }} development activity.</p>
            {% endif %}
        </div>

        <!-- Charts Section -->
        {% if charts %}
        <div class="section">
            <h2>📈 Analytics Overview</h2>
            
            {% if charts.language_distribution %}
            <div class="chart-container">
                {{ charts.language_distribution | safe }}
            </div>
            {% endif %}
            
            {% if charts.security_overview %}
            <div class="chart-container">
                {{ charts.security_overview | safe }}
            </div>
            {% endif %}
            
            {% if charts.activity_metrics %}
            <div class="chart-container">
                {{ charts.activity_metrics | safe }}
            </div>
            {% endif %}
        </div>
        {% endif %}

        <!-- Project Details -->
        <div class="section">
            <h2>📁 Project Details</h2>
            <div class="project-grid">
                {% for project in projects %}
                <div class="project-card {% if project.vulnerability_summary.vulnerable_packages > 0 %}vulnerable{% endif %}">
                    <h4>{{ project.name }}</h4>
                    <p><strong>Language:</strong> {{ project.primary_language | title }}</p>
                    <p><strong>Dependencies:</strong> {{ project.vulnerability_summary.total_dependencies | default(0) }}</p>
                    <p><strong>Stars:</strong> {{ project.github_metadata.stars | default(0) }}</p>
                    {% if project.vulnerability_summary.vulnerable_packages > 0 %}
                        <p><span class="badge danger">{{ project.vulnerability_summary.vulnerable_packages }} vulnerabilities</span></p>
                    {% else %}
                        <p><span class="badge success">Secure</span></p>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Recommendations -->
        {% if risk_metrics.vulnerable_projects > 0 %}
        <div class="recommendations">
            <h3>🔧 Recommended Actions</h3>
            <ul>
                <li><strong>Immediate:</strong> Review and update vulnerable dependencies in {{ risk_metrics.vulnerable_projects }} affected project{{ 's' if risk_metrics.vulnerable_projects > 1 else '' }}</li>
                <li><strong>Short-term:</strong> Implement automated dependency scanning in CI/CD pipelines</li>
                <li><strong>Long-term:</strong> Establish regular security review processes and dependency update schedules</li>
            </ul>
        </div>
        {% endif %}

        <div class="footer">
            <p>This report was automatically generated by Code Reporter. For detailed project analysis, refer to individual project reports.</p>
        </div>
    </div>
</body>
</html>'''

        # Write templates to files
        project_template_path = self.template_dir / 'project_report.html'
        executive_template_path = self.template_dir / 'executive_summary.html'
        
        if not project_template_path.exists():
            project_template_path.write_text(project_template)
        
        if not executive_template_path.exists():
            executive_template_path.write_text(executive_template)