"""Source Code Counter (SCC) integration for code metrics analysis."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional

from .logger import get_logger


class SCCAnalyzer:
    """Analyzes code metrics using the SCC tool."""
    
    def __init__(self):
        """Initialize the SCC analyzer and check tool availability."""
        self.enabled = self._check_scc_availability()
        self.logger = get_logger()
        
        if self.enabled:
            self.logger.debug("SCC tool found and available")
        else:
            self.logger.debug("SCC tool not available - code metrics will be skipped")
    
    def _check_scc_availability(self) -> bool:
        """Check if SCC tool is available on the system."""
        return shutil.which('scc') is not None
    
    def analyze_repository(self, repo_path: Path) -> Dict:
        """
        Analyze code metrics for a repository using SCC.
        
        Args:
            repo_path: Path to the cloned repository
            
        Returns:
            Dictionary containing SCC analysis results
        """
        result = {
            'success': False,
            'enabled': self.enabled,
            'error': None,
            'language_summary': [],
            'estimated_cost': 0.0,
            'estimated_schedule_months': 0.0,
            'estimated_people': 0.0,
            'totals': {
                'lines': 0,
                'code_lines': 0,
                'comment_lines': 0,
                'blank_lines': 0,
                'complexity': 0,
                'files': 0
            }
        }
        
        if not self.enabled:
            result['error'] = 'SCC tool not available'
            return result
        
        try:
            # Run SCC with JSON2 output format
            cmd = ['scc', '--format', 'json2', str(repo_path)]
            
            self.logger.debug(f"Running SCC analysis: {' '.join(cmd)}")
            
            process_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                check=True
            )
            
            # Parse JSON output
            scc_data = json.loads(process_result.stdout)
            
            result['success'] = True
            result['language_summary'] = scc_data.get('languageSummary', [])
            result['estimated_cost'] = scc_data.get('estimatedCost', 0.0)
            result['estimated_schedule_months'] = scc_data.get('estimatedScheduleMonths', 0.0)
            result['estimated_people'] = scc_data.get('estimatedPeople', 0.0)
            
            # Calculate totals from language summary
            totals = result['totals']
            for lang_data in result['language_summary']:
                totals['lines'] += lang_data.get('Lines', 0)
                totals['code_lines'] += lang_data.get('Code', 0)
                totals['comment_lines'] += lang_data.get('Comment', 0)
                totals['blank_lines'] += lang_data.get('Blank', 0)
                totals['complexity'] += lang_data.get('Complexity', 0)
                totals['files'] += lang_data.get('Count', 0)
            
            self.logger.debug(f"SCC analysis complete: {totals['lines']} lines, {totals['files']} files")
            
        except subprocess.TimeoutExpired:
            result['error'] = 'SCC analysis timed out'
            self.logger.warning(f"SCC analysis timed out for {repo_path}")
            
        except subprocess.CalledProcessError as e:
            result['error'] = f'SCC command failed: {e.stderr}'
            self.logger.warning(f"SCC analysis failed: {e.stderr}")
            
        except json.JSONDecodeError as e:
            result['error'] = f'Invalid JSON output from SCC: {e}'
            self.logger.warning(f"SCC JSON parsing failed: {e}")
            
        except Exception as e:
            result['error'] = f'Unexpected error: {str(e)}'
            self.logger.warning(f"SCC analysis failed with unexpected error: {e}")
        
        return result
    
    def format_cost(self, cost: float) -> str:
        """Format cost value for display."""
        if cost >= 1000000:
            return f"${cost/1000000:.1f}M"
        elif cost >= 1000:
            return f"${cost/1000:.0f}K"
        else:
            return f"${cost:.0f}"
    
    def format_schedule(self, months: float) -> str:
        """Format schedule months for display."""
        if months >= 12:
            years = months / 12
            return f"{years:.1f} years"
        else:
            return f"{months:.1f} months"
    
    def format_people(self, people: float) -> str:
        """Format people count for display."""
        if people < 0.1:
            return "< 0.1 people"
        elif people >= 1:
            return f"{people:.0f} people"
        else:
            return f"{people:.1f} people"