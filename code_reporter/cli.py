#!/usr/bin/env python3
"""Main CLI interface for Code Reporter."""

import os
import sys
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv

from .logger import init_logger, get_logger


@click.command()
@click.option(
    '--repo-list-file', 
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help='Path to file containing repository URLs (one per line)'
)
@click.option(
    '--output-dir',
    type=click.Path(path_type=Path),
    default='./reports',
    help='Output directory for generated reports'
)
@click.option(
    '--format',
    type=click.Choice(['html', 'pdf', 'both']),
    default='both',
    help='Report format to generate'
)
@click.option(
    '--env-file',
    type=click.Path(exists=True, path_type=Path),
    default='.env',
    help='Path to .env file for configuration'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose logging'
)
@click.option(
    '--llm',
    default='openai/gpt-5-mini',
    help='LLM model to use for executive summary generation (default: openai/gpt-5-minie)'
)
def main(
    repo_list_file: Path,
    output_dir: Path,
    format: str,
    env_file: Optional[Path],
    verbose: bool,
    llm: str
):
    """Analyze GitHub repositories and generate comprehensive reports."""
    
    # Load environment variables
    if env_file and env_file.exists():
        load_dotenv(env_file)
    else:
        load_dotenv()  # Load from .env if it exists
    
    # Initialize logging
    init_logger(verbose)
    logger = get_logger()
    
    # Validate configuration
    config = validate_config(verbose)
    if not config:
        sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.debug(f"Repository list: {repo_list_file}")
    logger.debug(f"Output directory: {output_dir}")
    logger.debug(f"Report format: {format}")
    
    # Import analysis modules
    from .repo_manager import RepositoryManager
    from .language_detector import LanguageDetector
    from .github_analyzer import GitHubAnalyzer
    from .dependency_analyzer import DependencyAnalyzer
    from .sentry_analyzer import SentryAnalyzer
    from .scc_analyzer import SCCAnalyzer
    from .readme_parser import ReadmeParser
    from .report_generator import ReportGenerator
    
    logger.info("Starting repository analysis")
    
    # Read repository list
    repos = read_repo_list(repo_list_file)
    logger.info(f"Found {len(repos)} repositories to analyze")
    
    for repo in repos:
        logger.debug(f"Repository: {repo}")
    
    # Initialize managers
    repo_manager = RepositoryManager(github_token=config['github_token'])
    language_detector = LanguageDetector()
    github_analyzer = GitHubAnalyzer()
    dependency_analyzer = DependencyAnalyzer()
    sentry_analyzer = SentryAnalyzer(
        auth_token=config['sentry']['auth_token'],
        organization_slug=os.getenv('SENTRY_ORG_SLUG')
    )
    scc_analyzer = SCCAnalyzer()
    readme_parser = ReadmeParser()
    
    # Analyze repositories
    analysis_results = {}
    
    def progress_callback(message):
        logger.debug(message)
    
    try:
        with repo_manager.clone_repositories(repos, progress_callback) as repo_infos:
            for repo_url, repo_info in repo_infos.items():
                logger.info(f"Analyzing {repo_info.full_name}")
                
                if not repo_info.success:
                    logger.info(f"Failed to clone {repo_info.full_name}: {repo_info.error}")
                    analysis_results[repo_url] = {
                        'success': False,
                        'error': repo_info.error,
                        'repo_info': repo_info
                    }
                    continue
                
                try:
                    # Detect languages and frameworks
                    language_info = language_detector.analyze_repository(repo_info.local_path)
                    
                    # Parse README for project description
                    readme_info = readme_parser.parse_repository(repo_info.local_path)
                    
                    # Analyze dependencies and vulnerabilities
                    dependency_info = dependency_analyzer.analyze_repository(repo_info.local_path, language_info)
                    
                    # Analyze GitHub statistics
                    github_stats = github_analyzer.analyze_repository(repo_info.owner, repo_info.name)
                    
                    # Analyze Sentry error data
                    logger.debug(f"Calling Sentry analyzer for {repo_info.owner}/{repo_info.name}")
                    sentry_stats = sentry_analyzer.analyze_repository(repo_info.owner, repo_info.name)
                    logger.debug(f"Sentry analysis result: success={sentry_stats.get('success', False)}, projects={len(sentry_stats.get('projects', []))}")
                    
                    # Analyze code metrics with SCC
                    logger.debug(f"Calling SCC analyzer for {repo_info.owner}/{repo_info.name}")
                    scc_stats = scc_analyzer.analyze_repository(repo_info.local_path)
                    logger.debug(f"SCC analysis result: success={scc_stats.get('success', False)}, lines={scc_stats.get('totals', {}).get('lines', 0)}")
                    
                    # Display results
                    if language_info['primary_language']:
                        primary = language_info['languages'][language_info['primary_language']]
                        logger.debug(f"Primary language: {language_info['primary_language'].title()}")
                        
                        if primary.get('version'):
                            logger.debug(f"Language version: {primary['version']}")
                        
                        if primary.get('frameworks'):
                            for framework, info in primary['frameworks'].items():
                                version_info = f" (v{info['version']})" if info['version'] != 'unknown' else ""
                                logger.debug(f"Framework: {framework.title()}{version_info}")
                    
                    # Display GitHub statistics
                    if github_stats['success']:
                        metadata = github_stats['metadata']
                        issues = github_stats['issues']
                        commits = github_stats['commits']
                        
                        logger.debug(f"GitHub stats: {metadata.get('stars', 0)} stars, {metadata.get('forks', 0)} forks")
                        if metadata.get('license'):
                            logger.debug(f"License: {metadata['license']}")
                        
                        logger.debug(f"Issues (past month): {issues['past_month']['created']} created, {issues['past_month']['resolved']} resolved")
                        if issues.get('avg_resolution_time', {}).get('days', 0) > 0:
                            logger.debug(f"Average issue resolution time: {issues['avg_resolution_time']['days']} days")
                        logger.debug(f"Commits (past month): {commits['past_month']['total']} commits by {commits['past_month']['unique_authors']} authors")
                        
                        if commits['top_contributors']:
                            logger.debug(f"Top contributor: {commits['top_contributors'][0]['name']} ({commits['top_contributors'][0]['commits']} commits)")
                    
                    # Display dependency and security information
                    summary = dependency_info['summary']
                    logger.debug(f"Dependencies: {summary['total_dependencies']} total")
                    
                    if summary['vulnerable_packages'] > 0:
                        logger.debug(f"Security alerts: {summary['vulnerable_packages']} vulnerable packages")
                        for vuln in dependency_info['vulnerabilities'][:3]:  # Show first 3
                            severity = vuln['vulnerability']['severity']
                            logger.debug(f"Vulnerability: {vuln['package']} v{vuln['version']}: {vuln['vulnerability']['summary'][:60]}...")
                    else:
                        logger.debug(f"Security: No known vulnerabilities found")
                    
                    if dependency_info['dependencies']:
                        for lang, lang_deps in dependency_info['dependencies'].items():
                            if lang_deps.get('detected'):
                                pkg_count = len(lang_deps.get('packages', {}))
                                dev_count = len(lang_deps.get('dev_packages', {}))
                                if pkg_count > 0:
                                    logger.debug(f"{lang.title()} dependencies: {pkg_count} packages" + (f", {dev_count} dev" if dev_count else ""))
                    
                    # Display Sentry error statistics
                    if sentry_stats['success'] and sentry_analyzer.enabled:
                        sentry_issues = sentry_stats['issues']
                        if sentry_issues['past_month']['total'] > 0:
                            logger.debug(f"Sentry errors (past month): {sentry_issues['past_month']['total']} total, {sentry_issues['past_month']['resolved']} resolved")
                            if sentry_issues['avg_resolution_time']['days'] > 0:
                                logger.debug(f"Average Sentry resolution time: {sentry_issues['avg_resolution_time']['days']} days")
                            if sentry_issues['events_count'] > 0:
                                logger.debug(f"Sentry event volume: {sentry_issues['events_count']} events")
                        else:
                            logger.debug(f"Sentry: No errors in past month")
                        
                        if sentry_stats.get('projects'):
                            project_names = [p['name'] for p in sentry_stats['projects']]
                            logger.debug(f"Sentry projects: {', '.join(project_names)}")
                    elif sentry_analyzer.enabled and not sentry_stats['success']:
                        logger.debug(f"Sentry analysis failed: {sentry_stats.get('error', 'Analysis failed')}")
                    
                    # Display SCC code metrics
                    if scc_stats['success'] and scc_analyzer.enabled:
                        totals = scc_stats['totals']
                        logger.debug(f"Code metrics: {totals['lines']} total lines, {totals['files']} files")
                        if scc_stats['estimated_cost'] > 0:
                            cost = scc_analyzer.format_cost(scc_stats['estimated_cost'])
                            schedule = scc_analyzer.format_schedule(scc_stats['estimated_schedule_months'])
                            logger.debug(f"COCOMO estimates: {cost}, {schedule}")
                    elif scc_analyzer.enabled and not scc_stats['success']:
                        logger.debug(f"SCC analysis failed: {scc_stats.get('error', 'Analysis failed')}")
                    
                    analysis_results[repo_url] = {
                        'success': True,
                        'repo_info': repo_info,
                        'language_info': language_info,
                        'readme_info': readme_info,
                        'github_stats': github_stats,
                        'dependency_info': dependency_info,
                        'sentry_stats': sentry_stats,
                        'scc_stats': scc_stats
                    }
                    
                except Exception as e:
                    logger.info(f"Analysis failed for {repo_info.full_name}: {str(e)}")
                    analysis_results[repo_url] = {
                        'success': False,
                        'error': str(e),
                        'repo_info': repo_info
                    }
    
    except KeyboardInterrupt:
        click.echo("\n⚠️ Analysis interrupted by user")
        return
    
    # Summary
    successful = sum(1 for result in analysis_results.values() if result['success'])
    logger.debug(f"Analysis complete: {successful}/{len(repos)} repositories successful")
    
    # Generate reports if we have successful analyses
    if successful > 0:
        logger.debug("Generating reports")
        logger.debug("Generating LLM-powered executive summary")
        logger.debug(f"Using model: {llm}")
        
        report_generator = ReportGenerator(output_dir, llm_model=llm)
        report_paths = report_generator.generate_reports(analysis_results, format)
        
        logger.debug("Reports generated:")
        for report_type, path in report_paths.items():
            if report_type == 'executive_summary':
                logger.debug(f"Executive Summary: {path}")
            elif report_type == 'combined_report':
                logger.debug(f"Combined Report: {path}")
            else:
                logger.debug(f"Project Report ({report_type.replace('https://github.com/', '')}): {path}")
        
        logger.info(f"All reports saved to: {output_dir}")


def validate_config(verbose: bool = False) -> dict:
    """Validate required configuration and environment variables."""
    config = {}
    errors = []
    
    # Check for LLM API keys (at least one required)
    openai_key = os.getenv('OPENAI_API_KEY')
    anthropic_key = os.getenv('ANTHROPIC_API_KEY')
    
    if not openai_key and not anthropic_key:
        errors.append("Either OPENAI_API_KEY or ANTHROPIC_API_KEY must be set")
    
    config['llm_api_keys'] = {
        'openai': openai_key,
        'anthropic': anthropic_key
    }
    
    # Optional Sentry configuration
    config['sentry'] = {
        'client_key': os.getenv('SENTRY_CLIENT_KEY'),
        'auth_token': os.getenv('SENTRY_AUTH_TOKEN'),
        'org_slug': os.getenv('SENTRY_ORG_SLUG')
    }
    
    # Optional GitHub token for private repos
    config['github_token'] = os.getenv('GITHUB_TOKEN')
    
    if verbose:
        logger = get_logger()
        logger.debug("Configuration status:")
        logger.debug(f"  OpenAI API Key: {'✅' if openai_key else '❌'}")
        logger.debug(f"  Anthropic API Key: {'✅' if anthropic_key else '❌'}")
        logger.debug(f"  GitHub Token: {'✅' if config['github_token'] else '❌'}")
        logger.debug(f"  Sentry Client Key: {'✅' if config['sentry']['client_key'] else '❌'}")
        logger.debug(f"  Sentry Auth Token: {'✅' if config['sentry']['auth_token'] else '❌'}")
        logger.debug(f"  Sentry Org Slug: {'✅' if config['sentry']['org_slug'] else '❌'}")
    
    if errors:
        print("❌ Configuration errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return None
    
    return config


def read_repo_list(file_path: Path) -> list[str]:
    """Read repository URLs from file, one per line."""
    repos = []
    
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                # Basic URL validation
                if not (line.startswith('https://github.com/') or line.startswith('git@github.com:')):
                    print(f"⚠️ Warning: Line {line_num} doesn't look like a GitHub URL: {line}", file=sys.stderr)
                repos.append(line)
    
    return repos


if __name__ == '__main__':
    main()
