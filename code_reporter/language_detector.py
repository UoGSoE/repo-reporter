"""Language and framework detection functionality."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
import tomli
import yaml


class LanguageDetector:
    """Detects programming languages and frameworks in repositories."""
    
    def __init__(self):
        self.detectors = {
            'php': self._detect_php,
            'python': self._detect_python,
            'golang': self._detect_golang
        }
    
    def analyze_repository(self, repo_path: Path) -> Dict:
        """
        Analyze a repository to detect languages and frameworks.
        
        Args:
            repo_path: Path to the cloned repository
            
        Returns:
            Dictionary containing language and framework information
        """
        results = {
            'primary_language': None,
            'languages': {},
            'frameworks': {},
            'versions': {}
        }
        
        # Detect each language
        for lang_name, detector in self.detectors.items():
            detection = detector(repo_path)
            if detection['detected']:
                results['languages'][lang_name] = detection
        
        # Determine primary language based on priority and confidence
        results['primary_language'] = self._determine_primary_language(results['languages'])
        
        return results
    
    def _determine_primary_language(self, languages: Dict) -> Optional[str]:
        """
        Determine the primary language based on detection confidence and priority.
        
        Priority order: PHP/Laravel -> Python -> Golang
        """
        priority_order = ['php', 'python', 'golang']
        
        for lang in priority_order:
            if lang in languages and languages[lang]['detected']:
                # Extra weight for framework detection
                if languages[lang].get('frameworks'):
                    return lang
        
        # Fall back to first detected language
        for lang in priority_order:
            if lang in languages and languages[lang]['detected']:
                return lang
        
        return None
    
    def _detect_php(self, repo_path: Path) -> Dict:
        """Detect PHP and Laravel."""
        result = {
            'detected': False,
            'version': None,
            'frameworks': {},
            'package_files': [],
            'confidence': 0
        }
        
        # Check for composer.json (primary indicator)
        composer_json = repo_path / 'composer.json'
        if composer_json.exists():
            result['detected'] = True
            result['package_files'].append('composer.json')
            result['confidence'] += 50
            
            try:
                with open(composer_json, 'r') as f:
                    composer_data = json.load(f)
                
                # Extract PHP version requirement
                php_version = self._extract_php_version(composer_data)
                if php_version:
                    result['version'] = php_version
                    result['confidence'] += 20
                
                # Check for Laravel
                laravel_info = self._detect_laravel(composer_data, repo_path)
                if laravel_info:
                    result['frameworks']['laravel'] = laravel_info
                    result['confidence'] += 30
                
            except Exception as e:
                # Still detected as PHP, but with lower confidence
                result['confidence'] = 30
        
        # Check for PHP files as fallback
        php_files = list(repo_path.glob('**/*.php'))
        if php_files and not result['detected']:
            result['detected'] = True
            result['confidence'] = 20
        elif php_files:
            result['confidence'] += min(len(php_files), 20)
        
        # Check for artisan file (Laravel indicator)
        if (repo_path / 'artisan').exists() and result['detected']:
            result['confidence'] += 25
            if 'laravel' not in result['frameworks']:
                result['frameworks']['laravel'] = {'version': 'unknown', 'detected_via': 'artisan_file'}
        
        return result
    
    def _extract_php_version(self, composer_data: Dict) -> Optional[str]:
        """Extract PHP version from composer.json."""
        require = composer_data.get('require', {})
        php_constraint = require.get('php', '')
        
        if php_constraint:
            # Extract version number from constraint (e.g., "^8.1" -> "8.1")
            version_match = re.search(r'(\d+\.\d+)', php_constraint)
            if version_match:
                return version_match.group(1)
        
        return None
    
    def _detect_laravel(self, composer_data: Dict, repo_path: Path) -> Optional[Dict]:
        """Detect Laravel framework and version."""
        require = composer_data.get('require', {})
        
        # Check for Laravel framework in dependencies
        for package in require:
            if 'laravel/framework' in package:
                version = require[package]
                return {
                    'version': self._clean_version(version),
                    'detected_via': 'composer_dependency'
                }
        
        # Check for Laravel installer or Laravel project type
        if composer_data.get('type') == 'laravel-project':
            return {
                'version': 'unknown',
                'detected_via': 'project_type'
            }
        
        # Check for Laravel-specific files
        if (repo_path / 'config' / 'app.php').exists():
            app_config = repo_path / 'config' / 'app.php'
            try:
                content = app_config.read_text()
                if 'Laravel' in content:
                    return {
                        'version': 'unknown',
                        'detected_via': 'config_files'
                    }
            except:
                pass
        
        return None
    
    def _detect_python(self, repo_path: Path) -> Dict:
        """Detect Python and common frameworks."""
        result = {
            'detected': False,
            'version': None,
            'frameworks': {},
            'package_files': [],
            'confidence': 0
        }
        
        # Check for package files
        package_files = [
            'requirements.txt',
            'pyproject.toml',
            'Pipfile',
            'setup.py',
            'poetry.lock',
            'pipenv'
        ]
        
        for package_file in package_files:
            if (repo_path / package_file).exists():
                result['detected'] = True
                result['package_files'].append(package_file)
                result['confidence'] += 25
        
        # Check for Python files as fallback
        py_files = list(repo_path.glob('**/*.py'))
        if py_files and not result['detected']:
            result['detected'] = True
            result['confidence'] = 15
        elif py_files:
            result['confidence'] += min(len(py_files), 15)
        
        if result['detected']:
            # Extract version and frameworks
            result['version'] = self._extract_python_version(repo_path)
            result['frameworks'] = self._detect_python_frameworks(repo_path)
            
            if result['frameworks']:
                result['confidence'] += 20
        
        return result
    
    def _extract_python_version(self, repo_path: Path) -> Optional[str]:
        """Extract Python version from various config files."""
        
        # Check pyproject.toml
        pyproject = repo_path / 'pyproject.toml'
        if pyproject.exists():
            try:
                with open(pyproject, 'rb') as f:
                    data = tomli.load(f)
                
                # Check project.requires-python
                requires_python = data.get('project', {}).get('requires-python')
                if requires_python:
                    version_match = re.search(r'(\d+\.\d+)', requires_python)
                    if version_match:
                        return version_match.group(1)
                
                # Check tool.poetry.dependencies.python
                poetry_python = data.get('tool', {}).get('poetry', {}).get('dependencies', {}).get('python')
                if poetry_python:
                    version_match = re.search(r'(\d+\.\d+)', poetry_python)
                    if version_match:
                        return version_match.group(1)
                        
            except Exception:
                pass
        
        # Check .python-version
        python_version_file = repo_path / '.python-version'
        if python_version_file.exists():
            try:
                version = python_version_file.read_text().strip()
                version_match = re.search(r'(\d+\.\d+)', version)
                if version_match:
                    return version_match.group(1)
            except Exception:
                pass
        
        return None
    
    def _detect_python_frameworks(self, repo_path: Path) -> Dict:
        """Detect Python frameworks like Django, Flask, etc."""
        frameworks = {}
        
        # Check requirements files for framework dependencies
        framework_patterns = {
            'django': [r'[Dd]jango==?', r'^django$', r'[Dd]jango>'],
            'flask': [r'[Ff]lask==?', r'^flask$', r'[Ff]lask>'],
            'fastapi': [r'[Ff]ast[Aa][Pp][Ii]==?', r'^fastapi$'],
            'tornado': [r'[Tt]ornado==?', r'^tornado$']
        }
        
        # Check requirements.txt
        req_file = repo_path / 'requirements.txt'
        if req_file.exists():
            try:
                content = req_file.read_text()
                for framework, patterns in framework_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.MULTILINE):
                            version_match = re.search(f'{pattern}([\\d\\.]+)', content, re.IGNORECASE)
                            version = version_match.group(1) if version_match else 'unknown'
                            frameworks[framework] = {
                                'version': version,
                                'detected_via': 'requirements.txt'
                            }
                            break
            except Exception:
                pass
        
        # Check for Django-specific files
        if (repo_path / 'manage.py').exists() or (repo_path / 'django').exists():
            if 'django' not in frameworks:
                frameworks['django'] = {
                    'version': 'unknown',
                    'detected_via': 'project_structure'
                }
        
        return frameworks
    
    def _detect_golang(self, repo_path: Path) -> Dict:
        """Detect Golang and frameworks."""
        result = {
            'detected': False,
            'version': None,
            'frameworks': {},
            'package_files': [],
            'confidence': 0
        }
        
        # Check for go.mod (primary indicator)
        go_mod = repo_path / 'go.mod'
        if go_mod.exists():
            result['detected'] = True
            result['package_files'].append('go.mod')
            result['confidence'] += 50
            
            try:
                content = go_mod.read_text()
                
                # Extract Go version
                go_version_match = re.search(r'go (\d+\.\d+)', content)
                if go_version_match:
                    result['version'] = go_version_match.group(1)
                    result['confidence'] += 20
                
                # Detect frameworks from dependencies
                result['frameworks'] = self._detect_go_frameworks(content)
                if result['frameworks']:
                    result['confidence'] += 30
                    
            except Exception:
                result['confidence'] = 30
        
        # Check for go.sum
        if (repo_path / 'go.sum').exists() and result['detected']:
            result['package_files'].append('go.sum')
            result['confidence'] += 10
        
        # Check for Go files as fallback
        go_files = list(repo_path.glob('**/*.go'))
        if go_files and not result['detected']:
            result['detected'] = True
            result['confidence'] = 20
        elif go_files:
            result['confidence'] += min(len(go_files), 15)
        
        return result
    
    def _detect_go_frameworks(self, go_mod_content: str) -> Dict:
        """Detect Go frameworks from go.mod content."""
        frameworks = {}
        
        framework_patterns = {
            'gin': r'github\.com/gin-gonic/gin',
            'echo': r'github\.com/labstack/echo',
            'gorilla': r'github\.com/gorilla/mux',
            'fiber': r'github\.com/gofiber/fiber',
            'chi': r'github\.com/go-chi/chi'
        }
        
        for framework, pattern in framework_patterns.items():
            match = re.search(f'{pattern}\\s+v([\\d\\.]+)', go_mod_content)
            if match:
                frameworks[framework] = {
                    'version': match.group(1),
                    'detected_via': 'go.mod'
                }
        
        return frameworks
    
    def _clean_version(self, version_string: str) -> str:
        """Clean version string by removing constraint operators."""
        # Remove common version constraint prefixes
        cleaned = re.sub(r'^[\^\~\>\<\=\!\s]+', '', version_string)
        # Extract just the version number
        version_match = re.search(r'(\d+(?:\.\d+)*)', cleaned)
        return version_match.group(1) if version_match else cleaned
