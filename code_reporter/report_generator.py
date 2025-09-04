"""HTML report generation functionality."""

import json
import math
import re
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
from .config import load_config
from .logger import get_logger


class ReportGenerator:
    """Generates HTML reports from analysis results."""
    
    def __init__(self, output_dir: Path, llm_model: str = "openai/gpt-5-mini"):
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
        
        # Add custom number formatting filter
        def number_format_filter(value):
            """Format numbers with thousands separators."""
            if value is None:
                return "0"
            try:
                return f"{int(value):,}"
            except (ValueError, TypeError):
                return str(value)
        
        # Add custom currency formatting filter
        def currency_format_filter(value):
            """Format currency values with appropriate units (K/M)."""
            if value is None or value == 0:
                return "$0"
            
            try:
                value = float(value)
                if value >= 1000000:
                    # Format as millions
                    millions = value / 1000000
                    if millions >= 10:
                        return f"${millions:.0f}M"
                    else:
                        return f"${millions:.1f}M"
                elif value >= 1000:
                    # Format as thousands
                    thousands = value / 1000
                    if thousands >= 100:
                        return f"${thousands:.0f}K"
                    else:
                        return f"${thousands:.0f}K"
                else:
                    # Less than 1000, show as dollars
                    return f"${value:.0f}"
            except (ValueError, TypeError):
                return str(value)
        
        self.jinja_env.filters['markdown'] = markdown_filter
        self.jinja_env.filters['number_format'] = number_format_filter
        self.jinja_env.filters['currency_format'] = currency_format_filter
        
        # Add custom timeline formatting filter (months -> Xm or X(.5)y, rounded up)
        def timeline_format_filter(value):
            try:
                months = float(value or 0)
            except (ValueError, TypeError):
                return "0m"
            if months < 12:
                return f"{int(math.ceil(months))}m"
            years = months / 12.0
            # round up to nearest half-year
            half_up = math.ceil(years * 2) / 2.0
            if half_up.is_integer():
                return f"{int(half_up)}y"
            return f"{half_up}y"

        self.jinja_env.filters['timeline_format'] = timeline_format_filter
        
        # Create templates if they don't exist
        self._ensure_templates()

        # Load runtime config
        self.config = load_config()
    
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

    def _simplify_license_name(self, license_name: str) -> str:
        """Map raw license strings to broad categories for manager-friendly charts.

        - Collapses variants (e.g., BSD-2/3 -> BSD, LGPL versions -> LGPL).
        - Attempts to detect SPDX-like expressions and multi-license strings; if
          multiple distinct families are present, returns 'Mixed'.
        """
        if not license_name:
            return 'Unknown'

        text = str(license_name)
        lower = text.lower()

        # If the string clearly contains multiple licenses/operators, treat as mixed
        if any(sep in lower for sep in ['/', ' or ', ' and ', '||', ',', ' with ', '(', ')']):
            parts = re.split(r"\bor\b|\band\b|\||/|,|\(|\)|\bwith\b", lower)
            families: set[str] = set()
            for p in parts:
                p = p.strip()
                if not p:
                    continue
                families.add(self._simplify_license_name_single(p))
            families.discard('Other')
            families.discard('Unknown')
            return next(iter(families)) if len(families) == 1 else 'Mixed'

        return self._simplify_license_name_single(lower)

    def _simplify_license_name_single(self, lower_name: str) -> str:
        """Simplify a single license token (expects lowercase)."""
        ln = lower_name.strip()
        if not ln:
            return 'Unknown'
        # Check more specific identifiers before generic ones
        if 'mit' in ln or 'isc' in ln:
            return 'MIT'
        if 'apache' in ln:
            return 'Apache'
        if 'bsd' in ln:
            return 'BSD'
        if 'lgpl' in ln:
            return 'LGPL'
        if 'agpl' in ln:
            return 'AGPL'
        if 'gpl' in ln:
            return 'GPL'
        if 'mozilla' in ln or 'mpl' in ln:
            return 'MPL'
        if 'unlicense' in ln or 'public domain' in ln:
            return 'Public Domain'
        if 'proprietary' in ln or 'commercial' in ln:
            return 'Proprietary'
        if 'unknown' in ln:
            return 'Unknown'
        return 'Other'

    def _simplify_license_distribution(self, distribution: Dict[str, int]) -> Dict[str, int]:
        """Aggregate a license distribution dict into simplified families."""
        simplified: Dict[str, int] = {}
        for raw, count in (distribution or {}).items():
            key = self._simplify_license_name(raw)
            simplified[key] = simplified.get(key, 0) + int(count or 0)
        return simplified
    
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
                },
                'scc_metrics': {
                    'projects_with_scc': 0,
                    'total_lines': 0,
                    'total_code_lines': 0,
                    'total_comment_lines': 0,
                    'total_blank_lines': 0,
                    'total_files': 0,
                    'total_complexity': 0,
                    'total_estimated_cost': 0.0,
                    'total_estimated_schedule_months': 0.0,
                    'total_estimated_people': 0.0
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
            readme_info = result.get('readme_info', {})
            github_stats = result.get('github_stats', {})
            dependency_info = result.get('dependency_info', {})
            sentry_stats = result.get('sentry_stats', {})
            scc_stats = result.get('scc_stats', {})
            
            project_data = {
                'success': True,
                'name': repo_info.name,
                'owner': repo_info.owner,
                'full_name': repo_info.full_name,
                'url': repo_url,
                'primary_language': language_info.get('primary_language'),
                'language_details': language_info.get('languages', {}),
                'readme_info': readme_info,
                'github_metadata': github_stats.get('metadata', {}),
                'github_issues': github_stats.get('issues', {}),
                'github_commits': github_stats.get('commits', {}),
                'dependencies': dependency_info.get('dependencies', {}),
                'vulnerability_summary': dependency_info.get('summary', {}),
                'vulnerabilities': dependency_info.get('vulnerabilities', []),
                'dependency_licenses': dependency_info.get('licenses', {}),
                'sentry_issues': sentry_stats.get('issues', {}),
                'sentry_projects': sentry_stats.get('projects', []),
                'sentry_enabled': sentry_stats.get('success', False),
                'scc_metrics': scc_stats.get('totals', {}),
                'scc_language_summary': scc_stats.get('language_summary', []),
                'scc_estimated_cost': scc_stats.get('estimated_cost', 0.0),
                'scc_estimated_schedule_months': scc_stats.get('estimated_schedule_months', 0.0),
                'scc_estimated_people': scc_stats.get('estimated_people', 0.0),
                'scc_enabled': scc_stats.get('success', False)
            }

            # Split vulnerabilities into production vs dev-only for clearer rendering
            vulns_all = project_data['vulnerabilities'] or []
            project_data['vulnerabilities_prod'] = [v for v in vulns_all if not v.get('dev_dependency')]
            project_data['vulnerabilities_dev'] = [v for v in vulns_all if v.get('dev_dependency')]
            
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
        # Use direct-only dependency count for headline portfolio totals
        summary['total_dependencies'] += vuln_summary.get('total_dependencies', 0)
        # Track total production vulnerabilities (findings) across portfolio
        summary['total_vulnerabilities'] += len(project_data.get('vulnerabilities_prod', []) )
        
        # Track unique dependencies (direct only; exclude dev and transitive)
        dependencies = project_data.get('dependencies', {})
        for language, dep_categories in dependencies.items():
            if isinstance(dep_categories, dict):
                packages = dep_categories.get('packages', {}) or {}
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
        
        # SCC code metrics
        if project_data.get('scc_enabled'):
            summary['scc_metrics']['projects_with_scc'] += 1
            
            scc_metrics = project_data.get('scc_metrics', {})
            summary['scc_metrics']['total_lines'] += scc_metrics.get('lines', 0)
            summary['scc_metrics']['total_code_lines'] += scc_metrics.get('code_lines', 0)
            summary['scc_metrics']['total_comment_lines'] += scc_metrics.get('comment_lines', 0)
            summary['scc_metrics']['total_blank_lines'] += scc_metrics.get('blank_lines', 0)
            summary['scc_metrics']['total_files'] += scc_metrics.get('files', 0)
            summary['scc_metrics']['total_complexity'] += scc_metrics.get('complexity', 0)
            
            # COCOMO estimates
            summary['scc_metrics']['total_estimated_cost'] += project_data.get('scc_estimated_cost', 0.0)
            summary['scc_metrics']['total_estimated_schedule_months'] += project_data.get('scc_estimated_schedule_months', 0.0)
            summary['scc_metrics']['total_estimated_people'] += project_data.get('scc_estimated_people', 0.0)
    
    def _generate_charts(self, processed_data: Dict) -> Dict:
        """Generate chart data for the reports."""
        charts = {}
        summary = processed_data['summary']
        
        # Technology distribution chart
        # Prefer SCC language breakdown (Code lines by language) for a more granular view.
        # Fallback to primary-language counts if SCC isn't available.
        scc_lang_totals: Dict[str, int] = {}
        for project in processed_data['projects'].values():
            for lang in project.get('scc_language_summary', []) or []:
                # Use Code lines as a better proxy for real code volume
                original_name = lang.get('Name')
                code_lines = int(lang.get('Code', 0) or 0)
                # Apply language filter and canonicalization from config
                if original_name and self.config.is_language_reportable(original_name):
                    name = self.config.canonical_language(original_name) or original_name
                    scc_lang_totals[name] = scc_lang_totals.get(name, 0) + code_lines

        if scc_lang_totals:
            # Apply min-lines threshold from config
            filtered_totals = {k: v for k, v in scc_lang_totals.items() if v >= self.config.min_language_lines}
            totals_to_use = filtered_totals or scc_lang_totals  # fallback if everything filtered out
            # Sort and group tail for readability in a pie
            sorted_items = sorted(totals_to_use.items(), key=lambda x: x[1], reverse=True)
            top_n = 12
            top_items = sorted_items[:top_n]
            other_total = sum(v for _, v in sorted_items[top_n:])
            names = [k for k, _ in top_items]
            values = [int(v) for _, v in top_items]
            if other_total > 0:
                names.append('Other')
                values.append(int(other_total))

            fig_lang = go.Figure(data=[go.Pie(
                labels=names,
                values=values,
                textinfo='label+percent',
                hovertemplate='<b>%{label}</b><br>Code lines: %{value:,}<extra></extra>'
            )])
            # Remove plot title for a cleaner card layout
            fig_lang.update_layout(title=None)
            charts['language_distribution'] = fig_lang.to_html(include_plotlyjs=False, div_id="lang-chart")
        elif summary['languages']:
            # Fallback: primary languages distribution
            fig_lang = px.pie(
                values=list(summary['languages'].values()),
                names=list(summary['languages'].keys()),
                title=None
            )
            fig_lang.update_layout(title=None)
            charts['language_distribution'] = fig_lang.to_html(include_plotlyjs=False, div_id="lang-chart")
        
        # Dependency license distribution bar chart (executive summary)
        if summary['dependency_license_distribution']:
            logger = get_logger()
            logger.debug(f"Executive summary chart data: {summary['dependency_license_distribution']}")
            
            # Group licenses by simplified names and aggregate counts
            simplified_licenses = self._simplify_license_distribution(summary['dependency_license_distribution'])
            
            # Ensure values are proper native Python integers for Plotly
            exec_chart_values = [int(v) if v is not None else 0 for v in simplified_licenses.values()]
            exec_chart_names = list(simplified_licenses.keys())
            # Force to native Python types to avoid numpy encoding issues
            exec_chart_values = [int(x) for x in exec_chart_values]
            logger.debug(f"Executive chart values: {exec_chart_values}, names: {exec_chart_names}")
            
            # Create DataFrame explicitly to avoid encoding issues
            import pandas as pd
            # Render as a pie chart for easier at-a-glance reading
            exec_df = pd.DataFrame({
                'license': exec_chart_names,
                'count': exec_chart_values
            })
            fig_dep_licenses = go.Figure(data=[go.Pie(
                labels=exec_chart_names,
                values=exec_chart_values,
                textinfo='label+percent',
                hovertemplate='<b>%{label}</b><br>Dependencies: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            # Remove title to avoid duplication with surrounding header
            fig_dep_licenses.update_layout(title=None)
            charts['dependency_license_distribution'] = fig_dep_licenses.to_html(include_plotlyjs=False, div_id="dep-license-chart")
        
        # Portfolio value chart (COCOMO estimated cost by project)
        value_labels: List[str] = []
        value_values: List[float] = []
        for project in processed_data['projects'].values():
            cost = float(project.get('scc_estimated_cost', 0.0) or 0.0)
            if cost > 0 and project.get('success'):
                value_labels.append(project.get('name', 'Unknown'))
                value_values.append(cost)

        if value_values:
            # Limit number of slices for readability; group the rest under "Other"
            items = list(zip(value_labels, value_values))
            items.sort(key=lambda x: x[1], reverse=True)
            top_n = 12
            top_items = items[:top_n]
            other_total = sum(v for _, v in items[top_n:])
            labels_plot = [lbl for lbl, _ in top_items]
            values_plot = [val for _, val in top_items]
            if other_total > 0:
                labels_plot.append('Other')
                values_plot.append(other_total)

            fig_value = go.Figure(data=[go.Pie(
                labels=labels_plot,
                values=values_plot,
                textinfo='label+percent',
                hovertemplate='<b>%{label}</b><br>Estimated Value: $%{value:,.0f}<extra></extra>'
            )])
            # Remove title for a cleaner card header + plot combo
            fig_value.update_layout(title=None)
            charts['portfolio_value'] = fig_value.to_html(include_plotlyjs=False, div_id="portfolio-value-chart")
        else:
            # Fallback: retain the simple security overview
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
        
        # Development Activity Dashboard
        projects = list(processed_data['projects'].values())
        if projects:
            # Calculate activity scores for each project
            activity_data = []
            for project in projects:
                activity_score, breakdown = self._calculate_activity_score(project)
                activity_data.append({
                    'name': project['name'],
                    'score': max(activity_score, 0),
                    'breakdown': breakdown
                })

            # Sort
            activity_data.sort(key=lambda x: x['score'], reverse=True)

            # Remove zero-score items to avoid cluttering legend
            nonzero = [i for i in activity_data if i['score'] > 0]

            # If everything is zero, fall back to original simple bar
            if not nonzero:
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
            else:
                # Group small slices under "Other" based on config threshold
                total = sum(i['score'] for i in nonzero) or 1
                threshold = max(0.0, min(1.0, float(self.config.pie_small_slice_threshold)))
                keep = [i for i in nonzero if (i['score'] / total) >= threshold]
                other_items = [i for i in nonzero if (i['score'] / total) < threshold]

                # Keep list length reasonable (still group long tail)
                top_n = 12
                keep = keep[:top_n]
                if len(nonzero) > top_n:
                    other_items += nonzero[top_n:]

                labels = [item['name'] for item in keep]
                values = [item['score'] for item in keep]

                # Prepare customdata for detailed hover for kept items
                customdata = []
                for item in keep:
                    b = item['breakdown']
                    customdata.append([b['commits'], b['contributors'], b['sentry_events'], b['sentry_issues'], b['stars'], item['score']])

                if other_items:
                    labels.append('Other')
                    values.append(sum(i['score'] for i in other_items))
                    commits = sum(i['breakdown']['commits'] for i in other_items)
                    contributors = sum(i['breakdown']['contributors'] for i in other_items)
                    sentry_events = sum(i['breakdown']['sentry_events'] for i in other_items)
                    sentry_issues = sum(i['breakdown']['sentry_issues'] for i in other_items)
                    stars = sum(i['breakdown']['stars'] for i in other_items)
                    score_sum = sum(i['score'] for i in other_items)
                    customdata.append([commits, contributors, sentry_events, sentry_issues, stars, score_sum])

                fig_activity = go.Figure(data=[go.Pie(
                    labels=labels,
                    values=values,
                    textinfo='label+percent',
                    customdata=customdata,
                    hovertemplate=(
                        '<b>%{label}</b><br>'
                        'Activity Score Share: %{percent}<br>'
                        '<br><b>Details (aggregated)</b><br>'
                        '• Commits: %{customdata[0]}<br>'
                        '• Contributors: %{customdata[1]}<br>'
                        '• Sentry Events: %{customdata[2]}<br>'
                        '• Sentry Issues: %{customdata[3]}<br>'
                        '• Stars: %{customdata[4]}<br>'
                        '• Score: %{customdata[5]}'
                        '<extra></extra>'
                    )
                )])

                # Remove plot title to avoid overlap with card header
                fig_activity.update_layout(title=None)

                charts['activity_metrics'] = fig_activity.to_html(include_plotlyjs=False, div_id="activity-chart")
        
        return charts
    
    def _calculate_activity_score(self, project: Dict) -> tuple[int, Dict]:
        """
        Calculate a composite activity score (0-100) for a project based on:
        - Development activity (commits, contributors) - 50%
        - Production usage (Sentry events/issues) - 30% 
        - Community engagement (stars, GitHub issues) - 20%
        """
        
        # Extract data with safe defaults
        commits = project.get('github_commits', {}).get('past_month', {}).get('total', 0)
        contributors = project.get('github_commits', {}).get('past_month', {}).get('unique_authors', 0)
        stars = project.get('github_metadata', {}).get('stars', 0)
        github_issues = project.get('github_issues', {}).get('past_month', {}).get('created', 0)
        sentry_events = project.get('sentry_issues', {}).get('events_count', 0)
        sentry_issues = project.get('sentry_issues', {}).get('past_month', {}).get('total', 0)
        
        # Development Activity Score (0-50 points)
        # Commits: 0-30 commits = 0-30 points (capped at 30)
        commit_score = min(commits, 30) 
        # Contributors: 0-10 contributors = 0-20 points (capped at 10)
        contributor_score = min(contributors * 2, 20)
        dev_score = commit_score + contributor_score
        
        # Production Usage Score (0-30 points) 
        # Sentry events indicate active production usage
        # 0-100 events = 0-20 points, 0-10 issues = 0-10 points
        sentry_event_score = min(sentry_events / 5, 20)  # 5 events = 1 point
        sentry_issue_score = min(sentry_issues, 10)  # 1 issue = 1 point
        production_score = sentry_event_score + sentry_issue_score
        
        # Community Engagement Score (0-20 points)
        # Stars indicate project popularity/usage
        # GitHub issues indicate community engagement
        star_score = min(stars / 5, 15)  # 5 stars = 1 point, max 15
        github_issue_score = min(github_issues, 5)  # 1 issue = 1 point, max 5  
        engagement_score = star_score + github_issue_score
        
        # Total score (0-100)
        total_score = int(dev_score + production_score + engagement_score)
        
        # Return score and breakdown for hover details
        breakdown = {
            'commits': commits,
            'contributors': contributors, 
            'stars': stars,
            'sentry_events': sentry_events,
            'sentry_issues': sentry_issues
        }
        
        return total_score, breakdown
    
    def _generate_project_report(self, project_data: Dict) -> str:
        """Generate HTML report for a single project."""
        template = self.jinja_env.get_template('project_report.html')
        
        # Generate dependency license chart for this project
        project_dep_license_chart = None
        dep_licenses = project_data.get('dependency_licenses', {})
        if dep_licenses:
            logger = get_logger()
            logger.debug(f"Chart data (raw) for {project_data['name']}: {dep_licenses}")
            # Simplify to broad license families for easier reading
            dep_licenses = self._simplify_license_distribution(dep_licenses)
            logger.debug(f"Chart data (simplified) for {project_data['name']}: {dep_licenses}")
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
            'has_vulnerabilities': len(project_data.get('vulnerabilities_prod', [])) > 0,
            'vulnerability_count': len(project_data.get('vulnerabilities_prod', [])),
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
                    logger.debug(f"Chart data (raw) for {project_data['name']}: {dep_licenses}")
                    # Simplify to broad license families for easier reading
                    dep_licenses = self._simplify_license_distribution(dep_licenses)
                    logger.debug(f"Chart data (simplified) for {project_data['name']}: {dep_licenses}")
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
                    'has_vulnerabilities': len(project_data.get('vulnerabilities_prod', [])) > 0,
                    'vulnerability_count': len(project_data.get('vulnerabilities_prod', [])),
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
            
            {% if charts.portfolio_value %}
            <div class="chart-container">
                {{ charts.portfolio_value | safe }}
            </div>
            {% elif charts.security_overview %}
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
