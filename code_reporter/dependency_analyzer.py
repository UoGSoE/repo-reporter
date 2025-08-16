"""Dependency analysis and CVE detection functionality."""

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import requests
import tomli
import yaml


class DependencyAnalyzer:
    """Analyzes project dependencies and checks for security vulnerabilities."""
    
    def __init__(self):
        self.osv_api_base = "https://api.osv.dev/v1"
        self.session = requests.Session()
        # Cache for CVE lookups to avoid repeated API calls
        self._cve_cache = {}
    
    def analyze_repository(self, repo_path: Path, language_info: Dict) -> Dict:
        """
        Analyze repository dependencies and check for vulnerabilities.
        
        Args:
            repo_path: Path to the cloned repository
            language_info: Language detection results
            
        Returns:
            Dictionary containing dependency analysis results
        """
        result = {
            'dependencies': {},
            'vulnerabilities': [],
            'outdated_packages': [],
            'licenses': {},
            'summary': {
                'total_dependencies': 0,
                'vulnerable_packages': 0,
                'outdated_packages': 0
            }
        }
        
        # Analyze dependencies for each detected language
        for lang_name, lang_info in language_info.get('languages', {}).items():
            if not lang_info.get('detected'):
                continue
                
            if lang_name == 'php':
                php_deps = self._analyze_php_dependencies(repo_path)
                result['dependencies']['php'] = php_deps
            
            elif lang_name == 'python':
                python_deps = self._analyze_python_dependencies(repo_path)
                result['dependencies']['python'] = python_deps
            
            elif lang_name == 'golang':
                go_deps = self._analyze_golang_dependencies(repo_path)
                result['dependencies']['golang'] = go_deps
        
        # Check for vulnerabilities
        all_packages = self._flatten_dependencies(result['dependencies'])
        result['vulnerabilities'] = self._check_vulnerabilities(all_packages)
        
        # Collect license information for dependencies
        result['licenses'] = self._collect_dependency_licenses(all_packages, repo_path, language_info)
        
        # Update summary
        result['summary']['total_dependencies'] = len(all_packages)
        result['summary']['vulnerable_packages'] = len(result['vulnerabilities'])
        
        return result
    
    def _analyze_php_dependencies(self, repo_path: Path) -> Dict:
        """Analyze PHP dependencies from composer.json and composer.lock."""
        result = {
            'detected': False,
            'packages': {},
            'dev_packages': {},
            'package_files': []
        }
        
        # Check composer.json
        composer_json = repo_path / 'composer.json'
        if composer_json.exists():
            result['detected'] = True
            result['package_files'].append('composer.json')
            
            try:
                with open(composer_json, 'r') as f:
                    composer_data = json.load(f)
                
                # Extract dependencies
                require = composer_data.get('require', {})
                require_dev = composer_data.get('require-dev', {})
                
                result['packages'] = self._parse_php_packages(require)
                result['dev_packages'] = self._parse_php_packages(require_dev)
                
            except Exception as e:
                result['error'] = f"Failed to parse composer.json: {str(e)}"
        
        # Check composer.lock for exact versions
        composer_lock = repo_path / 'composer.lock'
        if composer_lock.exists():
            result['package_files'].append('composer.lock')
            try:
                with open(composer_lock, 'r') as f:
                    lock_data = json.load(f)
                
                # Override with exact versions from lock file
                packages = lock_data.get('packages', [])
                for package in packages:
                    name = package.get('name')
                    version = package.get('version', '').lstrip('v')
                    if name and version:
                        result['packages'][name] = {
                            'version': version,
                            'constraint': result['packages'].get(name, {}).get('constraint', ''),
                            'source': 'composer.lock'
                        }
                        
            except Exception:
                pass  # composer.lock parsing is optional
        
        return result
    
    def _parse_php_packages(self, packages: Dict) -> Dict:
        """Parse PHP package requirements."""
        result = {}
        for name, constraint in packages.items():
            # Skip PHP itself and extensions
            if name.startswith('php') or name.startswith('ext-'):
                continue
            
            version = self._extract_version_from_constraint(constraint)
            result[name] = {
                'version': version,
                'constraint': constraint,
                'source': 'composer.json'
            }
        
        return result
    
    def _analyze_python_dependencies(self, repo_path: Path) -> Dict:
        """Analyze Python dependencies from various files."""
        result = {
            'detected': False,
            'packages': {},
            'dev_packages': {},
            'package_files': []
        }
        
        # Check requirements.txt
        req_file = repo_path / 'requirements.txt'
        if req_file.exists():
            result['detected'] = True
            result['package_files'].append('requirements.txt')
            result['packages'].update(self._parse_requirements_txt(req_file))
        
        # Check pyproject.toml
        pyproject = repo_path / 'pyproject.toml'
        if pyproject.exists():
            result['detected'] = True
            result['package_files'].append('pyproject.toml')
            packages = self._parse_pyproject_toml(pyproject)
            result['packages'].update(packages.get('main', {}))
            result['dev_packages'].update(packages.get('dev', {}))
        
        # Check Pipfile
        pipfile = repo_path / 'Pipfile'
        if pipfile.exists():
            result['detected'] = True
            result['package_files'].append('Pipfile')
            packages = self._parse_pipfile(pipfile)
            result['packages'].update(packages.get('main', {}))
            result['dev_packages'].update(packages.get('dev', {}))
        
        return result
    
    def _parse_requirements_txt(self, req_file: Path) -> Dict:
        """Parse requirements.txt file."""
        packages = {}
        try:
            content = req_file.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    # Parse package==version or package>=version etc.
                    match = re.match(r'^([a-zA-Z0-9_.-]+)(.*)', line)
                    if match:
                        name = match.group(1)
                        constraint = match.group(2) or ''
                        version = self._extract_version_from_constraint(constraint)
                        packages[name] = {
                            'version': version,
                            'constraint': constraint,
                            'source': 'requirements.txt'
                        }
        except Exception:
            pass
        
        return packages
    
    def _parse_pyproject_toml(self, pyproject: Path) -> Dict:
        """Parse pyproject.toml dependencies."""
        packages = {'main': {}, 'dev': {}}
        try:
            with open(pyproject, 'rb') as f:
                data = tomli.load(f)
            
            # Check project dependencies
            project_deps = data.get('project', {}).get('dependencies', [])
            for dep in project_deps:
                name, constraint = self._parse_python_dependency(dep)
                if name:
                    packages['main'][name] = {
                        'version': self._extract_version_from_constraint(constraint),
                        'constraint': constraint,
                        'source': 'pyproject.toml'
                    }
            
            # Check optional dependencies (dev)
            optional_deps = data.get('project', {}).get('optional-dependencies', {})
            for group_name, deps in optional_deps.items():
                for dep in deps:
                    name, constraint = self._parse_python_dependency(dep)
                    if name:
                        packages['dev'][name] = {
                            'version': self._extract_version_from_constraint(constraint),
                            'constraint': constraint,
                            'source': f'pyproject.toml[{group_name}]'
                        }
            
            # Check poetry dependencies if present
            poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
            for name, constraint in poetry_deps.items():
                if name != 'python':
                    if isinstance(constraint, dict):
                        constraint_str = constraint.get('version', '')
                    else:
                        constraint_str = str(constraint)
                    
                    packages['main'][name] = {
                        'version': self._extract_version_from_constraint(constraint_str),
                        'constraint': constraint_str,
                        'source': 'pyproject.toml[poetry]'
                    }
            
        except Exception:
            pass
        
        return packages
    
    def _parse_pipfile(self, pipfile: Path) -> Dict:
        """Parse Pipfile dependencies."""
        packages = {'main': {}, 'dev': {}}
        try:
            content = pipfile.read_text()
            data = tomli.loads(content)
            
            # Main packages
            main_packages = data.get('packages', {})
            for name, constraint in main_packages.items():
                if isinstance(constraint, dict):
                    constraint_str = constraint.get('version', '')
                else:
                    constraint_str = str(constraint)
                
                packages['main'][name] = {
                    'version': self._extract_version_from_constraint(constraint_str),
                    'constraint': constraint_str,
                    'source': 'Pipfile'
                }
            
            # Dev packages
            dev_packages = data.get('dev-packages', {})
            for name, constraint in dev_packages.items():
                if isinstance(constraint, dict):
                    constraint_str = constraint.get('version', '')
                else:
                    constraint_str = str(constraint)
                
                packages['dev'][name] = {
                    'version': self._extract_version_from_constraint(constraint_str),
                    'constraint': constraint_str,
                    'source': 'Pipfile[dev]'
                }
                
        except Exception:
            pass
        
        return packages
    
    def _analyze_golang_dependencies(self, repo_path: Path) -> Dict:
        """Analyze Golang dependencies from go.mod."""
        result = {
            'detected': False,
            'packages': {},
            'dev_packages': {},
            'package_files': []
        }
        
        go_mod = repo_path / 'go.mod'
        if go_mod.exists():
            result['detected'] = True
            result['package_files'].append('go.mod')
            
            try:
                content = go_mod.read_text()
                
                # Parse require block
                require_match = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
                if require_match:
                    require_block = require_match.group(1)
                    for line in require_block.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('//'):
                            parts = line.split()
                            if len(parts) >= 2:
                                name = parts[0]
                                version = parts[1].lstrip('v')
                                result['packages'][name] = {
                                    'version': version,
                                    'constraint': parts[1],
                                    'source': 'go.mod'
                                }
                
                # Also parse single line requires
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('require ') and '(' not in line:
                        parts = line.replace('require ', '').split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1].lstrip('v')
                            result['packages'][name] = {
                                'version': version,
                                'constraint': parts[1],
                                'source': 'go.mod'
                            }
                            
            except Exception as e:
                result['error'] = f"Failed to parse go.mod: {str(e)}"
        
        return result
    
    def _parse_python_dependency(self, dep_string: str) -> Tuple[str, str]:
        """Parse a Python dependency string into name and constraint."""
        # Handle various formats: "package", "package==1.0", "package>=1.0", etc.
        match = re.match(r'^([a-zA-Z0-9_.-]+)(.*)', dep_string.strip())
        if match:
            return match.group(1), match.group(2) or ''
        return '', ''
    
    def _extract_version_from_constraint(self, constraint: str) -> str:
        """Extract a specific version number from a constraint string."""
        if not constraint:
            return 'unknown'
        
        # Remove constraint operators and extract version
        cleaned = re.sub(r'^[\^\~\>\<\=\!\s\*]+', '', constraint)
        version_match = re.search(r'(\d+(?:\.\d+)*(?:\.\d+)*)', cleaned)
        return version_match.group(1) if version_match else 'unknown'
    
    def _flatten_dependencies(self, dependencies: Dict) -> List[Dict]:
        """Flatten nested dependency structure into a list of packages."""
        packages = []
        
        for lang, lang_deps in dependencies.items():
            if not lang_deps.get('detected'):
                continue
                
            # Add main packages
            for name, info in lang_deps.get('packages', {}).items():
                packages.append({
                    'name': name,
                    'version': info['version'],
                    'language': lang,
                    'source': info['source'],
                    'dev': False
                })
            
            # Add dev packages
            for name, info in lang_deps.get('dev_packages', {}).items():
                packages.append({
                    'name': name,
                    'version': info['version'],
                    'language': lang,
                    'source': info['source'],
                    'dev': True
                })
        
        return packages
    
    def _check_vulnerabilities(self, packages: List[Dict]) -> List[Dict]:
        """Check packages for known vulnerabilities using OSV API."""
        vulnerabilities = []
        
        for package in packages:
            if package['version'] == 'unknown':
                continue
            
            # Create cache key
            cache_key = f"{package['language']}:{package['name']}:{package['version']}"
            
            if cache_key in self._cve_cache:
                vulns = self._cve_cache[cache_key]
            else:
                vulns = self._query_osv_api(package)
                self._cve_cache[cache_key] = vulns
            
            if vulns:
                vulnerabilities.extend([
                    {
                        'package': package['name'],
                        'version': package['version'],
                        'language': package['language'],
                        'vulnerability': vuln,
                        'dev_dependency': package['dev']
                    }
                    for vuln in vulns
                ])
        
        return vulnerabilities
    
    def _query_osv_api(self, package: Dict) -> List[Dict]:
        """Query OSV API for vulnerabilities."""
        try:
            # Map language to ecosystem
            ecosystem_map = {
                'python': 'PyPI',
                'php': 'Packagist',
                'golang': 'Go'
            }
            
            ecosystem = ecosystem_map.get(package['language'])
            if not ecosystem:
                return []
            
            # Query OSV API
            url = f"{self.osv_api_base}/query"
            payload = {
                "package": {
                    "name": package['name'],
                    "ecosystem": ecosystem
                },
                "version": package['version']
            }
            
            response = self.session.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulns', [])
                
                return [
                    {
                        'id': vuln.get('id'),
                        'summary': vuln.get('summary', 'No summary available'),
                        'severity': self._extract_severity(vuln),
                        'published': vuln.get('published'),
                        'modified': vuln.get('modified')
                    }
                    for vuln in vulns
                ]
            
        except Exception:
            # Don't fail the entire analysis if CVE lookup fails
            pass
        
        return []
    
    def _extract_severity(self, vuln: Dict) -> Optional[str]:
        """Extract severity from vulnerability data."""
        severity = vuln.get('database_specific', {}).get('severity')
        if severity:
            return severity
        
        # Check for CVSS scores
        for score in vuln.get('severity', []):
            if score.get('type') == 'CVSS_V3':
                return score.get('score', 'Unknown')
        
        return 'Unknown'
    
    def _collect_dependency_licenses(self, packages: List[Dict], repo_path: Path, language_info: Dict) -> Dict:
        """Collect license information for all dependencies."""
        license_distribution = {}
        license_cache = {}
        
        print(f"\n🔍 Starting license detection for {len(packages)} packages...")
        
        # Check if we have PHP packages and try composer licenses first
        php_packages = [p for p in packages if p['language'] == 'php']
        composer_licenses = {}
        
        if php_packages:
            composer_licenses = self._get_composer_licenses(repo_path)
            if composer_licenses:
                print(f"   🎯 Found composer license data for {len(composer_licenses)} packages")
        
        for package in packages:
            # Create cache key
            cache_key = f"{package['language']}:{package['name']}"
            
            if cache_key in license_cache:
                license_info = license_cache[cache_key]
                print(f"   📋 {package['name']} ({package['language']}): {license_info.get('license', 'Unknown')} [cached]")
            else:
                # For PHP packages, check composer data first
                if package['language'] == 'php' and package['name'] in composer_licenses:
                    license_info = composer_licenses[package['name']]
                    print(f"   🎯 {package['name']} ({package['language']}): {license_info.get('license', 'Unknown')} [composer]")
                else:
                    print(f"   🔍 Fetching license for {package['name']} ({package['language']})...")
                    license_info = self._get_package_license(package)
                
                license_cache[cache_key] = license_info
                
                if license_info:
                    license_name = license_info.get('license', 'Unknown')
                    print(f"      ✅ Found: {license_name}")
                    if 'raw_license' in license_info:
                        print(f"      📄 Raw license text (first 100 chars): {license_info['raw_license'][:100]}...")
                else:
                    print(f"      ❌ No license information found")
            
            if license_info:
                license_name = license_info.get('license', 'Unknown')
                if license_name and license_name != 'Unknown':
                    license_distribution[license_name] = license_distribution.get(license_name, 0) + 1
                else:
                    license_distribution['Unknown'] = license_distribution.get('Unknown', 0) + 1
            else:
                license_distribution['Unknown'] = license_distribution.get('Unknown', 0) + 1
        
        print(f"\n📊 License distribution summary: {license_distribution}")
        return license_distribution
    
    def _get_package_license(self, package: Dict) -> Optional[Dict]:
        """Get license information for a package from its registry."""
        try:
            language = package['language']
            name = package['name']
            
            # Handle known virtual/meta packages
            if self._is_virtual_package(name, language):
                return {
                    'license': 'Virtual Package',
                    'raw_license': 'This is a virtual/meta package',
                    'source': 'virtual_package'
                }
            
            if language == 'python':
                return self._get_pypi_license(name)
            elif language == 'php':
                return self._get_packagist_license(name)
            elif language == 'golang':
                return self._get_golang_license(name)
            
        except Exception:
            # Don't fail the entire analysis if license lookup fails
            pass
        
        return None
    
    def _is_virtual_package(self, name: str, language: str) -> bool:
        """Check if this is a known virtual/meta package."""
        virtual_packages = {
            'php': [
                'composer-runtime-api',
                'composer-plugin-api',
                'php'
            ],
            'python': [
                'python'
            ],
            'golang': []
        }
        
        return name in virtual_packages.get(language, [])
    
    def _get_composer_licenses(self, repo_path: Path) -> Dict:
        """Get license information using composer licenses command."""
        licenses = {}
        
        # Check if this is a PHP project with composer and lock file
        if not (repo_path / 'composer.json').exists():
            return licenses
        
        if not (repo_path / 'composer.lock').exists():
            print(f"   ℹ️ No composer.lock found - skipping composer licenses (probably a library/framework)")
            return licenses
        
        try:
            print(f"   🔍 Running composer licenses in {repo_path}...")
            
            # First try to run composer install if vendor directory doesn't exist
            vendor_path = repo_path / 'vendor'
            if not vendor_path.exists():
                print(f"   📦 Installing composer dependencies...")
                install_result = subprocess.run(
                    ['composer', 'install', '--no-dev', '--quiet'],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes for install
                )
                if install_result.returncode != 0:
                    print(f"   ❌ Composer install failed - falling back to API")
                    return licenses
            
            # Run composer licenses command
            result = subprocess.run(
                ['composer', 'licenses', '--format=json', '--no-dev'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                try:
                    composer_data = json.loads(result.stdout)
                    dependencies = composer_data.get('dependencies', [])
                    
                    print(f"   🔍 Composer data type: {type(composer_data)}")
                    print(f"   🔍 Dependencies type: {type(dependencies)}")
                    if isinstance(dependencies, dict):
                        print(f"   🔍 Sample dependency keys: {list(dependencies.keys())[:3]}")
                        if dependencies:
                            first_key = list(dependencies.keys())[0]
                            print(f"   🔍 Sample dependency structure: {first_key} -> {dependencies[first_key]}")
                    else:
                        print(f"   🔍 First few deps: {dependencies[:2] if len(dependencies) > 0 else 'None'}")
                    
                    for name, dep_info in dependencies.items():
                        if isinstance(dep_info, dict):
                            license_list = dep_info.get('license', [])
                        else:
                            license_list = dep_info if isinstance(dep_info, list) else [dep_info]
                        
                        if name and license_list:
                            # Join multiple licenses with " / "
                            license_text = ' / '.join(license_list) if isinstance(license_list, list) else str(license_list)
                            licenses[name] = {
                                'license': license_text,
                                'raw_license': str(license_list),
                                'source': 'composer_command'
                            }
                            print(f"      📄 {name}: {license_text}")
                        elif name:
                            licenses[name] = {
                                'license': 'Unknown',
                                'raw_license': 'No license in composer output',
                                'source': 'composer_no_license'
                            }
                            print(f"      ❓ {name}: No license info")
                    
                    print(f"   ✅ Composer licenses parsed: {len(licenses)} packages")
                    
                except json.JSONDecodeError as e:
                    print(f"   ❌ Failed to parse composer licenses JSON: {e}")
                    print(f"   📄 Raw output: {result.stdout[:200]}...")
                    
            else:
                print(f"   ❌ Composer licenses command failed (exit code {result.returncode})")
                if result.stderr:
                    print(f"   📄 Error: {result.stderr[:200]}...")
                    
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Composer licenses command timed out")
        except FileNotFoundError:
            print(f"   ❌ Composer command not found - falling back to API")
        except Exception as e:
            print(f"   ❌ Composer licenses error: {e}")
        
        return licenses
    
    def _clean_license_text(self, license_text: str) -> str:
        """Clean and normalize license text for display."""
        # If it's a very long license text (full license content), try to extract just the name
        if len(license_text) > 100:
            # Look for common license patterns - order matters!
            license_patterns = [
                (r'BSD.*3.*Clause', 'BSD-3-Clause'), 
                (r'BSD.*2.*Clause', 'BSD-2-Clause'),
                (r'Copyright.*Redistribution and use in source and binary forms', 'BSD'),
                (r'Apache.*License.*Version.*2', 'Apache-2.0'),
                (r'GPL.*v?3', 'GPL-3.0'),
                (r'GPL.*v?2', 'GPL-2.0'),
                (r'MIT License', 'MIT'),
                (r'MIT', 'MIT'),
                (r'LGPL', 'LGPL'),
                (r'ISC', 'ISC'),
                (r'Mozilla', 'MPL')
            ]
            
            for pattern, name in license_patterns:
                if re.search(pattern, license_text, re.IGNORECASE):
                    return name
            
            # If no pattern matches, truncate to first line or first 50 chars
            first_line = license_text.split('\n')[0].strip()
            if len(first_line) <= 50:
                return first_line
            else:
                return license_text[:47] + "..."
        
        return license_text
    
    def _get_pypi_license(self, package_name: str) -> Optional[Dict]:
        """Get license information from PyPI API."""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                info = data.get('info', {})
                
                # Debug: Show what license info is available
                license_from_api = info.get('license')
                classifiers = info.get('classifiers', [])
                license_classifiers = [c for c in classifiers if c.startswith('License ::')]
                print(f"      🔎 PyPI response - license field: {repr(license_from_api)}")
                print(f"      🔎 PyPI response - license classifiers: {license_classifiers}")
                
                # Try license field first
                license_text = info.get('license') or ''
                if isinstance(license_text, str):
                    license_text = license_text.strip()
                else:
                    license_text = ''
                
                if license_text and license_text.lower() not in ['unknown', '', 'none']:
                    # Clean up long license text
                    cleaned_license = self._clean_license_text(license_text)
                    return {
                        'license': cleaned_license,
                        'raw_license': license_text,
                        'source': 'pypi_license_field'
                    }
                
                # Fall back to classifiers
                classifiers = info.get('classifiers', [])
                for classifier in classifiers:
                    if classifier.startswith('License ::'):
                        # Extract license name from classifier
                        license_name = classifier.split('::')[-1].strip()
                        if license_name not in ['Other/Proprietary License']:
                            # Normalize common classifier names
                            if license_name == 'MIT License':
                                license_name = 'MIT'
                            elif license_name == 'BSD License':
                                license_name = 'BSD'
                            elif license_name == 'Apache Software License':
                                license_name = 'Apache-2.0'
                            
                            return {
                                'license': license_name,
                                'raw_license': classifier,
                                'source': 'pypi_classifier'
                            }
                
                # Try newer license fields
                license_expression = info.get('license_expression', '').strip()
                if license_expression:
                    return {
                        'license': license_expression,
                        'raw_license': license_expression,
                        'source': 'pypi_license_expression'
                    }
                
                # Debug: Show full info for packages with no license
                print(f"      🔎 No license found for {package_name}. Available info keys: {list(info.keys())}")
                license_related_fields = {k: v for k, v in info.items() if 'license' in k.lower()}
                print(f"      🔎 License-related fields: {license_related_fields}")
                if 'classifiers' in info:
                    all_classifiers = info.get('classifiers', [])
                    print(f"      🔎 All classifiers: {[c for c in all_classifiers if 'license' in c.lower() or 'License' in c]}")
                
                return {
                    'license': 'Unknown',
                    'raw_license': 'No license info found in PyPI data',
                    'source': 'pypi_not_found'
                }
        
        except Exception as e:
            print(f"      ⚠️ PyPI API error for {package_name}: {str(e)}")
            return {
                'license': 'Unknown',
                'raw_license': f'API Error: {str(e)}',
                'source': 'pypi_error'
            }
    
    def _get_packagist_license(self, package_name: str) -> Optional[Dict]:
        """Get license information from Packagist API."""
        try:
            url = f"https://packagist.org/packages/{package_name}.json"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                package_data = data.get('package', {})
                
                # Get latest version info
                versions = package_data.get('versions', {})
                if versions:
                    # Get the most recent stable version
                    latest_version = next(iter(versions.values()))
                    licenses = latest_version.get('license', [])
                    
                    if licenses:
                        # Join multiple licenses with " / "
                        license_text = ' / '.join(licenses)
                        return {
                            'license': license_text,
                            'raw_license': str(licenses),
                            'source': 'packagist'
                        }
                
                return {
                    'license': 'Unknown',
                    'raw_license': 'No license info found in Packagist data',
                    'source': 'packagist_not_found'
                }
        
        except Exception as e:
            print(f"      ⚠️ Packagist API error for {package_name}: {str(e)}")
            return {
                'license': 'Unknown',
                'raw_license': f'API Error: {str(e)}',
                'source': 'packagist_error'
            }
    
    def _get_golang_license(self, package_name: str) -> Optional[Dict]:
        """Get license information for Go packages."""
        try:
            # For Go packages, we can try to get license info from pkg.go.dev API
            # pkg.go.dev provides a JSON API for package metadata
            url = f"https://api.pkg.go.dev/v1/symbol/{package_name}@latest"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                # This API doesn't provide license info directly
                # For now, return Unknown for Go packages
                return {
                    'license': 'Unknown',
                    'raw_license': 'Go packages license detection not implemented yet',
                    'source': 'golang_not_implemented'
                }
            
            # Alternative: could try to parse go.mod for license info
            # or use GitHub API if the package is hosted there
            return {
                'license': 'Unknown',
                'raw_license': 'pkg.go.dev API did not return data',
                'source': 'golang_api_no_data'
            }
        
        except Exception as e:
            print(f"      ⚠️ Go package API error for {package_name}: {str(e)}")
            return {
                'license': 'Unknown',
                'raw_license': f'API Error: {str(e)}',
                'source': 'golang_error'
            }