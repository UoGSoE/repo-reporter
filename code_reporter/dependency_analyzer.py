"""Dependency analysis and CVE detection functionality."""

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import requests
import time
import tomli
import yaml
import os

from .logger import get_logger


class DependencyAnalyzer:
    """Analyzes project dependencies and checks for security vulnerabilities."""
    
    def __init__(self):
        self.osv_api_base = "https://api.osv.dev/v1"
        self.session = requests.Session()
        # Cache for CVE lookups to avoid repeated API calls
        self._cve_cache = {}
        # GitHub token for GHSA fallback (optional)
        self.github_token = os.getenv('GITHUB_TOKEN')
        self._ghsa_cache: Dict[str, Dict] = {}
    
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

        # Compute unique non-dev vulnerable packages for clearer managerial reporting
        unique_non_dev_packages = set()
        for finding in result['vulnerabilities']:
            if not finding.get('dev_dependency'):
                unique_non_dev_packages.add((finding.get('language'), finding.get('package')))

        # Update headline summary to exclude dev deps and use unique package count
        result['summary']['vulnerable_packages'] = len(unique_non_dev_packages)

        # Collect license information for dependencies (all: direct, dev, indirect)
        result['licenses'] = self._collect_dependency_licenses(all_packages, repo_path, language_info)
        
        # Compute headline counts: direct-only vs overall
        direct_only_count = 0
        for lang_deps in result['dependencies'].values():
            if isinstance(lang_deps, dict) and lang_deps.get('detected'):
                direct_only_count += len(lang_deps.get('packages', {}) or {})

        # Use direct-only for the headline dependency count
        result['summary']['total_dependencies'] = direct_only_count
        # Also expose full count (including dev + indirect) for internal use if needed
        result['summary']['total_dependencies_all'] = len(all_packages)
        
        return result
    
    def _analyze_php_dependencies(self, repo_path: Path) -> Dict:
        """Analyze PHP dependencies from composer.json and composer.lock."""
        result = {
            'detected': False,
            'packages': {},          # direct runtime deps from composer.json:require
            'dev_packages': {},      # dev deps from composer.json:require-dev (and their locks)
            'indirect_packages': {}, # transitive deps discovered via composer.lock
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

                # Override direct deps with exact versions; capture transitive separately
                packages = lock_data.get('packages', [])
                for package in packages:
                    name = package.get('name')
                    version = package.get('version', '').lstrip('v')
                    if name and version:
                        if name in result['packages']:
                            # Direct dependency: override with locked version
                            result['packages'][name] = {
                                'version': version,
                                'constraint': result['packages'].get(name, {}).get('constraint', ''),
                                'source': 'composer.lock'
                            }
                        else:
                            # Transitive dependency: record under indirect
                            result['indirect_packages'][name] = {
                                'version': version,
                                'constraint': '',
                                'source': 'composer.lock'
                            }

                # Handle dev packages from lock (override direct dev and include additional)
                packages_dev = lock_data.get('packages-dev', [])
                for package in packages_dev:
                    name = package.get('name')
                    version = package.get('version', '').lstrip('v')
                    if name and version:
                        prev = result['dev_packages'].get(name, {})
                        result['dev_packages'][name] = {
                            'version': version,
                            'constraint': prev.get('constraint', ''),
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
        """Analyze Golang dependencies from go.mod.

        - Direct requires are recorded under "packages".
        - Entries marked with "// indirect" are recorded under "indirect_packages"
          (transitive), so headline counts can focus on direct deps while we still
          collect licenses and vulnerabilities for the full graph.
        """
        result = {
            'detected': False,
            'packages': {},            # direct runtime deps
            'dev_packages': {},        # reserved for parity with other ecosystems
            'indirect_packages': {},   # transitive deps ("// indirect")
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
                            # Distinguish transitive lines: "... vX.Y.Z // indirect"
                            is_indirect = ' // indirect' in line
                            clean = line.split('//')[0].strip()
                            parts = clean.split()
                            if len(parts) >= 2:
                                name = parts[0]
                                version_token = parts[1]
                                version = version_token.lstrip('v')
                                target = result['indirect_packages' if is_indirect else 'packages']
                                target[name] = {
                                    'version': version,
                                    'constraint': version_token,
                                    'source': 'go.mod'
                                }
                
                # Also parse single line requires
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('require ') and '(' not in line:
                        body = line.replace('require ', '').strip()
                        is_indirect = ' // indirect' in body
                        clean = body.split('//')[0].strip()
                        parts = clean.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version_token = parts[1]
                            version = version_token.lstrip('v')
                            target = result['indirect_packages' if is_indirect else 'packages']
                            target[name] = {
                                'version': version,
                                'constraint': version_token,
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
        """Flatten nested dependency structure into a list of packages.

        Includes direct, dev, and indirect (transitive) dependencies when present.
        """
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
                    'dev': False,
                    'indirect': False
                })
            
            # Add dev packages
            for name, info in lang_deps.get('dev_packages', {}).items():
                packages.append({
                    'name': name,
                    'version': info['version'],
                    'language': lang,
                    'source': info['source'],
                    'dev': True,
                    'indirect': False
                })

            # Add indirect (transitive) packages if present
            for name, info in lang_deps.get('indirect_packages', {}).items():
                packages.append({
                    'name': name,
                    'version': info['version'],
                    'language': lang,
                    'source': info['source'],
                    'dev': False,
                    'indirect': True
                })

        return packages
    
    def _check_vulnerabilities(self, packages: List[Dict]) -> List[Dict]:
        """Check packages for known vulnerabilities using OSV batch API with fallback."""
        logger = get_logger()
        ecosystem_map = {
            'python': 'PyPI',
            'php': 'Packagist',
            'golang': 'Go'
        }

        # Build unique queries and index map
        queries = []
        index_to_pkg = []
        seen = set()
        for pkg in packages:
            if pkg['version'] == 'unknown':
                continue
            eco = ecosystem_map.get(pkg['language'])
            if not eco:
                continue
            key = (pkg['language'], pkg['name'], pkg['version'])
            if key in seen:
                continue
            seen.add(key)
            # Cache hit shortcut
            cache_key = f"{key[0]}:{key[1]}:{key[2]}"
            if cache_key in self._cve_cache:
                continue  # will be added from cache later
            queries.append({
                "package": {"name": pkg['name'], "ecosystem": eco},
                "version": pkg['version']
            })
            index_to_pkg.append(key)

        # Call batch endpoint in chunks
        batch_vulns_map = {}
        url = f"{self.osv_api_base}/querybatch"
        chunk_size = 100
        for i in range(0, len(queries), chunk_size):
            chunk = queries[i:i+chunk_size]
            attempt = 0
            while attempt < 3:
                try:
                    resp = self.session.post(url, json={"queries": chunk}, timeout=20)
                    if resp.status_code == 200:
                        data = resp.json()
                        results = data.get('results', [])
                        for j, res in enumerate(results):
                            idx = i + j
                            if idx >= len(index_to_pkg):
                                continue
                            key = index_to_pkg[idx]
                            vulns = res.get('vulns', []) or []
                            # Debug raw OSV result for this package/version
                            try:
                                logger.debug(f"OSV batch result for {key}: {len(vulns)} vulns")
                                for vv in vulns[:5]:  # limit debug noise
                                    dbs = vv.get('database_specific', {}) or {}
                                    logger.debug(
                                        f"  - id={vv.get('id')} severity_list={vv.get('severity')} db.severity={dbs.get('severity')}"
                                    )
                            except Exception:
                                pass
                            # Normalize vuln records similar to single query
                            norm = []
                            for v in vulns:
                                label = self._extract_severity_label(v)
                                score, score_type = self._extract_cvss_score(v)
                                if not label:
                                    # Try affected[].ecosystem_specific.severity
                                    label = self._extract_ecosystem_severity(v)
                                if not label and score is not None:
                                    label = self._derive_severity_from_score(score)
                                if not label and not score:
                                    # Try fetching full OSV advisory by ID
                                    vid = v.get('id')
                                    if vid:
                                        full = self._fetch_osv_by_id(vid)
                                        if full:
                                            label = self._extract_severity_label(full) or self._extract_ecosystem_severity(full)
                                            if not score:
                                                score, score_type = self._extract_cvss_score(full)
                                if not label:
                                    # GHSA fallback via GitHub API (if token available)
                                    vid = v.get('id') or ''
                                    if vid.startswith('GHSA-'):
                                        adv = self._fetch_github_advisory(vid)
                                        if adv:
                                            gh_label = (adv.get('severity') or '').title() if adv.get('severity') else None
                                            if not score and (adv.get('cvss') or {}).get('score'):
                                                try:
                                                    score = float((adv.get('cvss') or {}).get('score'))
                                                    score_type = 'CVSS_V3'
                                                except (TypeError, ValueError):
                                                    pass
                                            label = gh_label or label
                                try:
                                    logger.debug(f"Normalized OSV vuln id={v.get('id')} label={label} cvss={score} type={score_type}")
                                except Exception:
                                    pass
                                norm.append({
                                    'id': v.get('id'),
                                    'summary': v.get('summary', 'No summary available'),
                                    'severity': label or 'Unknown',
                                    'cvss_score': score,
                                    'cvss_type': score_type,
                                    'published': v.get('published'),
                                    'modified': v.get('modified')
                                })
                            self._cve_cache[f"{key[0]}:{key[1]}:{key[2]}"] = norm
                            batch_vulns_map[key] = norm
                        break
                    else:
                        attempt += 1
                        time.sleep(0.5 * (attempt))
                except Exception as e:
                    attempt += 1
                    if attempt >= 3:
                        logger.warning(f"OSV batch query failed after retries: {e}")
                    else:
                        time.sleep(0.5 * (attempt))

        # Aggregate all vulnerabilities from cache/batch per input package (preserve dev flag)
        vulnerabilities: List[Dict] = []
        for pkg in packages:
            if pkg['version'] == 'unknown':
                continue
            eco = ecosystem_map.get(pkg['language'])
            if not eco:
                continue
            cache_key = f"{pkg['language']}:{pkg['name']}:{pkg['version']}"
            vulns = self._cve_cache.get(cache_key)
            if vulns is None:
                # Fallback to single query if not cached from batch
                vulns = self._query_osv_api(pkg)
                self._cve_cache[cache_key] = vulns
            if vulns:
                for v in vulns:
                    vulnerabilities.append({
                        'package': pkg['name'],
                        'version': pkg['version'],
                        'language': pkg['language'],
                        'vulnerability': v,
                        'dev_dependency': pkg['dev']
                    })

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
                try:
                    logger = get_logger()
                    logger.debug(f"OSV single result for {package['language']}:{package['name']}:{package['version']}: {len(vulns)} vulns")
                    for vv in vulns[:5]:
                        dbs = vv.get('database_specific', {}) or {}
                        logger.debug(
                            f"  - id={vv.get('id')} severity_list={vv.get('severity')} db.severity={dbs.get('severity')}"
                        )
                except Exception:
                    pass
                
                results = []
                for vuln in vulns:
                    label = self._extract_severity_label(vuln)
                    score, score_type = self._extract_cvss_score(vuln)
                    if not label:
                        label = self._extract_ecosystem_severity(vuln)
                    if not label and score is not None:
                        label = self._derive_severity_from_score(score)
                    if not label and not score:
                        vid = vuln.get('id')
                        if vid:
                            full = self._fetch_osv_by_id(vid)
                            if full:
                                label = self._extract_severity_label(full) or self._extract_ecosystem_severity(full)
                                if not score:
                                    score, score_type = self._extract_cvss_score(full)
                    if not label:
                        vid = vuln.get('id') or ''
                        if vid.startswith('GHSA-'):
                            adv = self._fetch_github_advisory(vid)
                            if adv:
                                gh_label = (adv.get('severity') or '').title() if adv.get('severity') else None
                                if not score and (adv.get('cvss') or {}).get('score'):
                                    try:
                                        score = float((adv.get('cvss') or {}).get('score'))
                                        score_type = 'CVSS_V3'
                                    except (TypeError, ValueError):
                                        pass
                                label = gh_label or label
                    try:
                        logger = get_logger()
                        logger.debug(f"Normalized OSV vuln id={vuln.get('id')} label={label} cvss={score} type={score_type}")
                    except Exception:
                        pass
                    results.append({
                        'id': vuln.get('id'),
                        'summary': vuln.get('summary', 'No summary available'),
                        'severity': label or 'Unknown',
                        'cvss_score': score,
                        'cvss_type': score_type,
                        'published': vuln.get('published'),
                        'modified': vuln.get('modified')
                    })
                return results
            
        except Exception:
            # Don't fail the entire analysis if CVE lookup fails
            pass
        
        return []
    
    def _extract_severity_label(self, vuln: Dict) -> Optional[str]:
        """Extract textual severity label if present (normalize to standard levels)."""
        label = (vuln.get('database_specific', {}) or {}).get('severity')
        if not label:
            return None
        l = str(label).strip().upper()
        # Normalize common variants
        if l in ('CRITICAL',):
            return 'Critical'
        if l in ('HIGH',):
            return 'High'
        if l in ('MODERATE', 'MEDIUM'):
            return 'Medium'
        if l in ('LOW',):
            return 'Low'
        return l.title()

    def _extract_cvss_score(self, vuln: Dict) -> tuple[Optional[float], Optional[str]]:
        """Extract CVSS score (v3 preferred, fallback to v2). Returns (score, type)."""
        sev_list = vuln.get('severity', []) or []
        # Prefer v3
        for entry in sev_list:
            if entry.get('type') == 'CVSS_V3':
                raw = entry.get('score')
                # Some OSV entries provide a vector string rather than numeric score
                if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.replace('.', '', 1).isdigit()):
                    try:
                        return float(raw), 'CVSS_V3'
                    except (TypeError, ValueError):
                        pass
                # If it's a vector like "CVSS:3.1/...", skip numeric conversion here
                return None, 'CVSS_V3'
        # Fallback to v2
        for entry in sev_list:
            if entry.get('type') == 'CVSS_V2':
                raw = entry.get('score')
                if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.replace('.', '', 1).isdigit()):
                    try:
                        return float(raw), 'CVSS_V2'
                    except (TypeError, ValueError):
                        pass
                return None, 'CVSS_V2'
        
        # Other common locations (some OSV entries embed CVSS differently)
        # Top-level cvss object
        cvss = vuln.get('cvss') or {}
        for key in ('score', 'baseScore'):
            if key in cvss:
                try:
                    return float(cvss[key]), 'CVSS_V3'
                except (TypeError, ValueError):
                    pass
        # database_specific cvss object
        dbs = (vuln.get('database_specific') or {}).get('cvss') or {}
        for key in ('score', 'baseScore'):
            if key in dbs:
                try:
                    return float(dbs[key]), 'CVSS_V3'
                except (TypeError, ValueError):
                    pass
        return None, None

    def _derive_severity_from_score(self, score: float) -> str:
        """Map CVSS score to severity bucket (Critical/High/Medium/Low)."""
        try:
            s = float(score)
        except (TypeError, ValueError):
            return 'Unknown'
        if s >= 9.0:
            return 'Critical'
        if s >= 7.0:
            return 'High'
        if s >= 4.0:
            return 'Medium'
        if s > 0:
            return 'Low'
        return 'Unknown'

    def _extract_ecosystem_severity(self, vuln: Dict) -> Optional[str]:
        """Check affected[].ecosystem_specific.severity values and return highest."""
        order = {'CRITICAL': 4, 'HIGH': 3, 'MODERATE': 2, 'MEDIUM': 2, 'LOW': 1}
        best = None
        best_rank = 0
        for aff in vuln.get('affected', []) or []:
            sev = ((aff.get('ecosystem_specific') or {}).get('severity') or '').strip().upper()
            if not sev:
                continue
            rank = order.get(sev, 0)
            if rank > best_rank:
                best = sev
                best_rank = rank
        if best:
            if best == 'MODERATE':
                return 'Medium'
            return best.title()
        return None

    def _fetch_github_advisory(self, ghsa_id: str) -> Optional[Dict]:
        """Fetch advisory from GitHub by GHSA ID via GraphQL to get severity/CVSS."""
        if not self.github_token:
            return None
        if ghsa_id in self._ghsa_cache:
            return self._ghsa_cache[ghsa_id]
        url = 'https://api.github.com/graphql'
        query = {
            'query': 'query($id: String!) { securityAdvisory(ghsaId: $id) { severity cvss { score vectorString } } }',
            'variables': {'id': ghsa_id}
        }
        headers = {'Authorization': f'bearer {self.github_token}'}
        try:
            resp = self.session.post(url, json=query, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                adv = ((data or {}).get('data') or {}).get('securityAdvisory')
                if adv:
                    self._ghsa_cache[ghsa_id] = adv
                    logger = get_logger()
                    logger.debug(f"GitHub advisory fetched for {ghsa_id}: severity={adv.get('severity')} cvss={((adv.get('cvss') or {}).get('score'))}")
                    return adv
        except Exception:
            pass
        return None

    def _fetch_osv_by_id(self, vuln_id: str) -> Optional[Dict]:
        """Fetch full OSV advisory by ID for richer fields (severity, CVSS)."""
        try:
            url = f"{self.osv_api_base}/vulns/{vuln_id}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                logger = get_logger()
                dbs = (data.get('database_specific') or {})
                logger.debug(f"OSV by-id fetched for {vuln_id}: db.severity={dbs.get('severity')} severity_list={data.get('severity')}")
                return data
        except Exception:
            pass
        return None
    
    def _collect_dependency_licenses(self, packages: List[Dict], repo_path: Path, language_info: Dict) -> Dict:
        """Collect license information for all dependencies."""
        license_distribution = {}
        license_cache = {}
        
        logger = get_logger()
        logger.debug(f"Starting license detection for {len(packages)} packages")
        
        # Check if we have PHP packages and try composer licenses first
        php_packages = [p for p in packages if p['language'] == 'php']
        composer_licenses = {}
        
        if php_packages:
            composer_licenses = self._get_composer_licenses(repo_path)
            if composer_licenses:
                logger.debug(f"Found composer license data for {len(composer_licenses)} packages")
        
        for package in packages:
            # Create cache key
            cache_key = f"{package['language']}:{package['name']}"
            
            if cache_key in license_cache:
                license_info = license_cache[cache_key]
                logger.debug(f"License cached: {package['name']} ({package['language']}): {license_info.get('license', 'Unknown')}")
            else:
                # For PHP packages, check composer data first
                if package['language'] == 'php' and package['name'] in composer_licenses:
                    license_info = composer_licenses[package['name']]
                    logger.debug(f"License from composer: {package['name']} ({package['language']}): {license_info.get('license', 'Unknown')}")
                else:
                    logger.debug(f"Fetching license for {package['name']} ({package['language']})")
                    license_info = self._get_package_license(package)
                
                license_cache[cache_key] = license_info
                
                if license_info:
                    license_name = license_info.get('license', 'Unknown')
                    logger.debug(f"License found: {license_name}")
                    if 'raw_license' in license_info:
                        logger.debug(f"Raw license text (first 100 chars): {license_info['raw_license'][:100]}...")
                else:
                    logger.debug("No license information found")
            
            if license_info:
                license_name = license_info.get('license', 'Unknown')
                if license_name and license_name != 'Unknown':
                    license_distribution[license_name] = license_distribution.get(license_name, 0) + 1
                else:
                    license_distribution['Unknown'] = license_distribution.get('Unknown', 0) + 1
            else:
                license_distribution['Unknown'] = license_distribution.get('Unknown', 0) + 1
        
        logger = get_logger()
        logger.debug(f"License distribution summary: {license_distribution}")
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
        """Get license information for PHP packages preferring composer.lock.

        Strategy (fast/safe):
        1) Parse composer.lock for license fields (packages and packages-dev)
           without installing dependencies.
        2) For any packages still missing license info, attempt a lightweight
           `composer licenses --format=json` with safe flags (no scripts/plugins).
        3) Leave any unresolved packages to be handled by registry fallback
           (Packagist) in _get_package_license.
        """
        licenses: Dict[str, Dict] = {}

        # Require composer.json and lockfile to proceed
        if not (repo_path / 'composer.json').exists():
            return licenses
        lock_path = repo_path / 'composer.lock'
        if not lock_path.exists():
            logger = get_logger()
            logger.debug("No composer.lock found - skipping composer licenses")
            return licenses

        logger = get_logger()
        # Step 1: Parse composer.lock
        try:
            lock_data = json.loads(lock_path.read_text(encoding='utf-8'))
            for section in ('packages', 'packages-dev'):
                for pkg in lock_data.get(section, []) or []:
                    name = pkg.get('name')
                    lic = pkg.get('license')
                    if not name:
                        continue
                    if lic:
                        if isinstance(lic, list):
                            license_text = ' / '.join([str(x) for x in lic])
                            raw = str(lic)
                        else:
                            license_text = str(lic)
                            raw = str(lic)
                        licenses[name] = {
                            'license': license_text,
                            'raw_license': raw,
                            'source': 'composer_lock'
                        }
            if licenses:
                logger.debug(f"composer.lock licenses parsed for {len(licenses)} packages")
        except Exception as e:
            logger.debug(f"Failed to parse composer.lock for licenses: {e}")

        # Identify missing packages after lock parse (we only know the names later,
        # but composer licenses output can provide broader coverage if available).
        # We try running composer licenses just once; if it fails, we rely on Packagist.
        try:
            cmd = ['composer', 'licenses', '--format=json', '--no-dev', '--no-scripts', '--no-plugins']
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    composer_data = json.loads(result.stdout)
                    deps = composer_data.get('dependencies', {}) or {}
                    if isinstance(deps, dict):
                        for name, dep_info in deps.items():
                            # Only fill gaps not present from lockfile
                            if name in licenses:
                                continue
                            if isinstance(dep_info, dict):
                                license_list = dep_info.get('license', [])
                            else:
                                license_list = dep_info if isinstance(dep_info, list) else [dep_info]
                            if license_list:
                                license_text = ' / '.join(license_list) if isinstance(license_list, list) else str(license_list)
                                licenses[name] = {
                                    'license': license_text,
                                    'raw_license': str(license_list),
                                    'source': 'composer_command'
                                }
                    logger.debug(f"composer licenses filled {len([k for k,v in licenses.items() if v.get('source')=='composer_command'])} missing entries")
                except Exception as e:
                    logger.debug(f"Failed to parse composer licenses JSON: {e}")
            else:
                if result.stderr:
                    logger.debug(f"composer licenses stderr: {result.stderr[:200]}...")
        except subprocess.TimeoutExpired:
            logger.debug("composer licenses command timed out; skipping")
        except FileNotFoundError:
            logger.debug("composer not found; skipping CLI license pass")
        except Exception as e:
            logger.debug(f"composer licenses error: {e}")

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
                logger = get_logger()
                logger.debug(f"PyPI response - license field: {repr(license_from_api)}")
                logger.debug(f"PyPI response - license classifiers: {license_classifiers}")
                
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
                logger = get_logger()
                logger.debug(f"No license found for {package_name}. Available info keys: {list(info.keys())}")
                license_related_fields = {k: v for k, v in info.items() if 'license' in k.lower()}
                logger.debug(f"License-related fields: {license_related_fields}")
                if 'classifiers' in info:
                    all_classifiers = info.get('classifiers', [])
                    logger.debug(f"All classifiers: {[c for c in all_classifiers if 'license' in c.lower() or 'License' in c]}")
                
                return {
                    'license': 'Unknown',
                    'raw_license': 'No license info found in PyPI data',
                    'source': 'pypi_not_found'
                }
        
        except Exception as e:
            logger = get_logger()
            logger.warning(f"PyPI API error for {package_name}: {str(e)}")
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
            logger = get_logger()
            logger.warning(f"Packagist API error for {package_name}: {str(e)}")
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
            logger = get_logger()
            logger.warning(f"Go package API error for {package_name}: {str(e)}")
            return {
                'license': 'Unknown',
                'raw_license': f'API Error: {str(e)}',
                'source': 'golang_error'
            }
