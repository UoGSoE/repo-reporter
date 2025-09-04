"""LLM-powered analysis and summary generation."""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import litellm
import json
from jinja2 import Environment, FileSystemLoader
from .logger import get_logger


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
            return "anthropic/claude-3-5-sonnet-20241022"
        elif os.getenv('OPENAI_API_KEY'):
            return "openai/gpt-5-mini"
        else:
            raise ValueError("No LLM API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY")
    
    def _read_local_context(self) -> Optional[str]:
        """Read local context from local_context.txt file if it exists."""
        try:
            # Find project root by looking for main.py
            current_dir = Path(__file__).parent
            while current_dir != current_dir.parent:
                main_py_path = current_dir / "main.py"
                if main_py_path.exists():
                    # Found project root, check for local_context.txt
                    context_file = current_dir / "local_context.txt"
                    if context_file.exists():
                        content = context_file.read_text(encoding='utf-8').strip()
                        return content
                    break
                current_dir = current_dir.parent
        except Exception:
            # Silently fail if we can't read the context file
            pass
        return None
    
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
        
        # Read local context if available
        local_context = self._read_local_context()
        
        # Load and render the prompt template
        try:
            template = self.jinja_env.get_template('executive_summary_prompt.txt')
            prompt = template.render(
                context=context,
                context_json=json.dumps(context, indent=2),
                local_context=local_context
            )
        except Exception as e:
            # Fallback to hardcoded prompt if template fails
            local_context_section = ""
            if local_context:
                local_context_section = f"\nLOCAL CONTEXT:\n{local_context}\n"
            
            prompt = f"""You are a strategic technology advisor preparing an executive briefing for senior leadership.

You have been provided with individual project summaries and portfolio metrics. Synthesize this into a cohesive narrative.
{local_context_section}
PORTFOLIO DATA:
{json.dumps(context, indent=2)}

Write a short 3-4 paragraph executive summary that:
1. Opens with strategic context - the portfolio's overall health and trajectory
2. Identifies patterns across projects - common strengths, risks, or opportunities
3. Provides 2-3 actionable insights for leadership

Guidelines:
- Synthesize patterns, don't list individual projects
- Focus on business impact
- Use natural, engaging language
- Emphasize strategic decisions
- Incorporate the local context above to make the summary relevant to the organization

Remember: This is about the forest, not the trees."""

        try:
            litellm.drop_params = True
            params = {
                    "model": self.model,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "reasoning_effort": "medium",
                }
            if self.model.startswith("openai/"):
                params["verbosity"] = "low"

            response = litellm.completion(**params)
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            # Fallback to a basic summary if LLM fails
            return self._generate_fallback_summary(context)
    
    def generate_project_summary(self, project_data: Dict) -> str:
        """
        Generate a manager-friendly executive summary for a single project.
        
        Args:
            project_data: Individual project analysis data
            
        Returns:
            Concise executive summary
        """
        logger = get_logger()
        logger.debug(f"Starting project summary generation for: {project_data.get('name', 'Unknown')}")
        
        # Load and render the project summary prompt template
        try:
            template = self.jinja_env.get_template('project_summary_prompt.txt')
            prompt = template.render(
                project=project_data,
                project_json=json.dumps(project_data, indent=2)
            )
            logger.debug(f"Template rendered successfully, prompt length: {len(prompt)} characters")
        except Exception as e:
            logger.debug(f"Template rendering failed, using fallback prompt: {e}")
            # Fallback to simple prompt if template fails
            description = project_data.get('github_metadata', {}).get('description', 'No description available')
            language = project_data.get('primary_language', 'Unknown')
            
            prompt = f"""Write a 2-3 sentence executive summary for a manager about this software project:

Project: {project_data['name']}
Description: {description}
Technology: {language}

Focus on business value, current status, and any concerns for management attention. Keep it under 100 words."""
            logger.debug(f"Fallback prompt length: {len(prompt)} characters")

        try:
            logger.debug(f"Calling LLM with model: {self.model}")
            # Prepare parameters, handling O-series model limitations
            params = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            }
            
            # Only add temperature for non-O-series models
            if not self.model.startswith('openai/o'):
                params["temperature"] = 0.3
            
            logger.debug(f"LLM parameters: {json.dumps({k: v for k, v in params.items() if k != 'messages'}, indent=2)}")
            # litellm._turn_on_debug() 
            response = litellm.completion(**params)
            
            result = response.choices[0].message.content.strip()
            logger.debug(f"LLM response received, length: {len(result)} characters")
            logger.debug(f"LLM response content: '{result[:100]}{'...' if len(result) > 100 else ''}'")
            
            return result
            
        except Exception as e:
            # Final fallback
            logger.warning(f"Project summary LLM call failed: {e}")
            fallback = f"Active {project_data.get('primary_language', 'software')} project with {project_data.get('vulnerability_summary', {}).get('total_dependencies', 0)} dependencies and {project_data.get('vulnerability_summary', {}).get('vulnerable_packages', 0)} security issues."
            logger.debug(f"Using fallback summary: {fallback}")
            return fallback
    
    def _prepare_llm_context(self, processed_data: Dict) -> Dict:
        """Prepare structured context data for LLM analysis."""
        summary = processed_data['summary']
        projects = processed_data['projects']
        
        # Collect project summaries for narrative synthesis
        project_summaries = []
        vulnerable_projects_count = 0
        high_activity_count = 0
        
        # Track dependency usage across projects (for shared deps and vuln roll-ups)
        dep_usage: Dict[tuple, Dict[str, Any]] = {}
        php_composer_present = False
        
        for project in projects.values():
            if not project.get('success'):
                continue
            
            # Collect LLM-generated project summaries if available
            if project.get('llm_project_summary'):
                project_summaries.append({
                    'name': project['name'],
                    'summary': project['llm_project_summary'],
                    'language': project.get('primary_language', 'Unknown'),
                    'has_vulnerabilities': project.get('vulnerability_summary', {}).get('vulnerable_packages', 0) > 0
                })
            
            # Count high-level metrics
            if project.get('vulnerability_summary', {}).get('vulnerable_packages', 0) > 0:
                vulnerable_projects_count += 1
            
            commits = project.get('github_commits', {}).get('past_month', {}).get('total', 0)
            if commits >= 10:
                high_activity_count += 1
            
            # Aggregate dependency usage
            deps = project.get('dependencies', {}) or {}
            if 'php' in deps:
                php_composer_present = True
            project_id = project.get('full_name') or project.get('name')
            if isinstance(deps, dict):
                for lang, dep_categories in deps.items():
                    if not isinstance(dep_categories, dict):
                        continue
                    for category, packages in dep_categories.items():
                        if not isinstance(packages, dict):
                            continue
                        is_dev = (category == 'dev_packages')
                        for pkg_name in packages.keys():
                            key = (lang, pkg_name)
                            entry = dep_usage.setdefault(key, {
                                'language': lang,
                                'name': pkg_name,
                                'projects': set(),
                                'prod_projects': set(),
                                'dev_projects': set(),
                                'vulns_total': 0,
                                'vulns_prod': 0,
                                'severity_max': None,
                            })
                            entry['projects'].add(project_id)
                            if is_dev:
                                entry['dev_projects'].add(project_id)
                            else:
                                entry['prod_projects'].add(project_id)
            
            # Aggregate vulnerabilities per dependency
            for v in project.get('vulnerabilities', []) or []:
                lang = v.get('language')
                pkg = v.get('package')
                if not lang or not pkg:
                    continue
                key = (lang, pkg)
                entry = dep_usage.setdefault(key, {
                    'language': lang,
                    'name': pkg,
                    'projects': set(),
                    'prod_projects': set(),
                    'dev_projects': set(),
                    'vulns_total': 0,
                    'vulns_prod': 0,
                    'severity_max': None,
                })
                entry['vulns_total'] += 1
                if not v.get('dev_dependency'):
                    entry['vulns_prod'] += 1
                sev = (v.get('vulnerability') or {}).get('severity')
                # Compute severity max
                rank_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                new_rank = rank_map.get(str(sev).upper(), 0)
                cur_rank = rank_map.get(str(entry['severity_max']).upper(), 0) if entry['severity_max'] else 0
                if new_rank > cur_rank:
                    entry['severity_max'] = str(sev) if sev else entry['severity_max']
        
        # Calculate portfolio-level insights
        total_projects = summary['successful_analyses']
        tech_diversity_score = len(summary['languages']) + len(summary['frameworks'])
        
        # Determine portfolio maturity based on various factors
        portfolio_maturity = "emerging"
        if summary['activity_metrics']['total_commits'] > 50:
            portfolio_maturity = "active"
        if summary['activity_metrics']['total_stars'] > 5000:
            portfolio_maturity = "mature"
        
        # Aggregate severity buckets for production vulnerabilities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for project in projects.values():
            if not project.get('success'):
                continue
            for v in (project.get('vulnerabilities') or []):
                if v.get('dev_dependency'):
                    continue
                sev = ((v.get('vulnerability') or {}).get('severity') or "UNKNOWN").upper()
                sev = sev if sev in sev_counts else "UNKNOWN"
                sev_counts[sev] += 1

        context = {
            # Project narratives for synthesis
            'project_summaries': project_summaries,
            
            # High-level portfolio metrics only
            'portfolio_overview': {
                'total_projects': total_projects,
                'technology_diversity': tech_diversity_score,
                'portfolio_maturity': portfolio_maturity,
                'primary_technologies': list(summary['languages'].keys())[:3],
                'main_frameworks': list(summary['frameworks'].keys())[:3] if summary['frameworks'] else []
            },
            
            # Simplified risk assessment
            'risk_assessment': {
                'projects_at_risk': vulnerable_projects_count,
                'risk_percentage': round((vulnerable_projects_count / max(total_projects, 1)) * 100, 1),
                'total_vulnerabilities': summary['total_vulnerabilities'],
                'severity_counts': {
                    'critical': sev_counts['CRITICAL'],
                    'high': sev_counts['HIGH'],
                    'medium': sev_counts['MEDIUM'],
                    'low': sev_counts['LOW'],
                    'unknown': sev_counts['UNKNOWN'],
                }
            },
            
            # Activity summary
            'activity_summary': {
                'high_activity_projects': high_activity_count,
                'total_monthly_commits': summary['activity_metrics']['total_commits'],
                'active_contributors': summary['activity_metrics']['total_contributors']
            },
            
            # Business metrics
            'business_metrics': {
                'total_stars': summary['activity_metrics']['total_stars'],
                'total_forks': summary['activity_metrics']['total_forks'],
                # Prefer unique dependency count to avoid inflating footprint
                'unique_dependency_count': summary.get('unique_dependency_count', len(summary.get('unique_dependencies', []))),
                # Also include total usages across projects for context
                'total_dependency_usages': summary['total_dependencies'],
                'has_error_monitoring': summary['sentry_metrics']['projects_with_sentry'] > 0,
                'monitored_projects': summary['sentry_metrics']['projects_with_sentry']
            }
        }
        
        # Add COCOMO estimates if available
        if summary.get('scc_metrics') and summary['scc_metrics'].get('projects_with_scc') > 0:
            context['business_metrics']['estimated_value'] = summary['scc_metrics']['total_estimated_cost']
            context['business_metrics']['code_volume'] = summary['scc_metrics']['total_lines']
        
        # Dependency aggregates and profile
        total_unique = context['business_metrics']['unique_dependency_count']
        shared_deps = []
        vulnerable_agg = []
        shared_unique_count = 0
        for entry in dep_usage.values():
            projects_affected = len(entry['projects'])
            if projects_affected >= 2:
                shared_unique_count += 1
                shared_deps.append({
                    'name': entry['name'],
                    'language': entry['language'],
                    'projects': projects_affected,
                    'vulns_total': entry['vulns_total'],
                    'vulns_prod': entry['vulns_prod'],
                    'severity_max': entry['severity_max'],
                })
            if entry['vulns_total'] > 0:
                vulnerable_agg.append({
                    'name': entry['name'],
                    'language': entry['language'],
                    'projects_affected': projects_affected,
                    'vulns_total': entry['vulns_total'],
                    'vulns_prod': entry['vulns_prod'],
                    'severity_max': entry['severity_max'],
                })
        shared_deps.sort(key=lambda x: (x['projects'], x['vulns_prod'], x['vulns_total']), reverse=True)
        vulnerable_agg.sort(key=lambda x: (x['vulns_prod'], x['projects_affected']), reverse=True)
        shared_ratio = round(shared_unique_count / max(total_unique, 1), 3)
        context['dependency_aggregates'] = {
            'shared_dependencies': shared_deps[:20],
            'vulnerable_packages_agg': vulnerable_agg[:20],
            'total_unique': total_unique,
            'shared_unique': shared_unique_count,
        }
        context['deps_profile'] = {
            'shared_ratio': shared_ratio
        }
        context['tooling'] = {
            'php_composer': php_composer_present
        }

        return context
    
    def _generate_fallback_summary(self, context: Dict) -> str:
        """Generate a more natural summary if LLM is unavailable."""
        # Extract key metrics from the new context structure
        total_projects = context['portfolio_overview']['total_projects']
        portfolio_maturity = context['portfolio_overview']['portfolio_maturity']
        tech_diversity = context['portfolio_overview']['technology_diversity']
        vuln_projects = context['risk_assessment']['projects_at_risk']
        risk_pct = context['risk_assessment']['risk_percentage']
        monthly_commits = context['activity_summary']['total_monthly_commits']
        high_activity = context['activity_summary']['high_activity_projects']
        
        # Opening with portfolio characterization
        if portfolio_maturity == "mature":
            opening = f"Your technology portfolio comprises {total_projects} established projects with strong market presence and community engagement. "
        elif portfolio_maturity == "active":
            opening = f"The portfolio encompasses {total_projects} actively developed projects demonstrating solid momentum across the technology stack. "
        else:
            opening = f"This emerging portfolio of {total_projects} projects represents your organization's evolving technology initiatives. "
        
        # Technology and activity assessment
        if tech_diversity > 5:
            tech_assessment = f"The diverse technology stack spanning {tech_diversity} different languages and frameworks suggests a flexible, polyglot approach to solution development. "
        else:
            tech_assessment = f"With a focused technology stack, the portfolio maintains consistency and specialization in its technical approach. "
        
        if high_activity > total_projects * 0.5:
            activity_assessment = f"Strong development velocity across {high_activity} highly active projects indicates healthy team engagement and continuous delivery practices."
        elif monthly_commits > 20:
            activity_assessment = f"Steady development activity with {monthly_commits} commits this month reflects consistent progress and maintenance across the portfolio."
        else:
            activity_assessment = f"Current development patterns suggest a maintenance-focused phase with selective enhancements."
        
        # Risk and recommendations
        if vuln_projects > 0:
            if risk_pct > 50:
                risk_statement = f"\n\nImmediate attention is required for security remediation, with {vuln_projects} projects ({risk_pct:.0f}% of portfolio) containing known vulnerabilities. This represents a significant exposure that should be addressed through a coordinated security sprint. "
            else:
                risk_statement = f"\n\nWhile the portfolio shows overall strength, {vuln_projects} {'project requires' if vuln_projects == 1 else 'projects require'} security updates to maintain optimal risk posture. "
        else:
            risk_statement = "\n\nThe portfolio maintains a clean security profile with no detected vulnerabilities, positioning the organization well for compliance and risk management. "
        
        # Business context if available
        business_context = ""
        if context['business_metrics'].get('estimated_value'):
            value = context['business_metrics']['estimated_value']
            if value > 1000000:
                business_context = f"The substantial codebase represents an estimated ${value/1000000:.1f}M in development investment, underscoring the strategic importance of proper governance and maintenance strategies."
            elif value > 100000:
                business_context = f"With an estimated development value of ${value/1000:.0f}K, the portfolio represents a significant technical asset requiring strategic oversight."
        
        # Combine into natural flowing summary
        summary = opening + tech_assessment + activity_assessment + risk_statement
        if business_context:
            summary += business_context
        
        return summary
