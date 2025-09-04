# Code Reporter

A comprehensive tool that analyzes GitHub repositories and generates detailed reports covering code quality, security vulnerabilities, dependencies, development activity, and production error tracking via Sentry integration.

## Features

### Code Analysis
- **Multi-language support**: PHP/Laravel, Python, Golang with automatic version detection
- **Framework detection**: Automatically identifies and analyzes framework versions
- **Dependency analysis**: Parses package files (composer.json, requirements.txt, go.mod)
- **License detection**: Identifies project and dependency licenses

### Security Analysis
- **Vulnerability scanning**: CVE detection via OSV API
- **Dependency security**: Identifies vulnerable packages with severity ratings
- **Security alerts**: Highlighted warnings in reports

### Code Metrics (SCC Integration)
- **Lines of code analysis**: Total lines, code lines, comments, and complexity metrics
- **COCOMO estimates**: Development cost, timeline, and team size projections
- **Language breakdown**: Detailed metrics by programming language
- **Portfolio totals**: Executive summary with cross-project code metrics

### GitHub Integration
- **Activity metrics**: Commit history, contributor analysis, issue tracking
- **Repository metadata**: Stars, forks, license information  
- **Issue resolution**: Business-focused metrics like resolution times and rates

### Sentry Integration (NEW!)
- **Error tracking**: Production error monitoring and statistics
- **Issue resolution**: Tracks error resolution times and rates
- **Project mapping**: Smart matching between GitHub repos and Sentry projects
- **Event volume**: Monitors error event counts and trends

### Professional Reports
- **HTML reports**: Interactive reports with Plotly charts
- **PDF generation**: Print-ready executive summaries
- **LLM-powered insights**: AI-generated project and executive summaries
- **Local context integration**: Customize summaries with organizational details
- **Responsive design**: Mobile-friendly layouts

## Quick Start

### 1. Prerequisites

Before installation, ensure you have:
- **Python 3.13+**
- **GitHub CLI**: Required for repository cloning (both public and private repos)
  - Install from [cli.github.com](https://cli.github.com/) 
  - Authenticate with `gh auth login`
  - Verify with `gh auth status`

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/UoGSoE/repo-reporter.git
cd repo-reporter

# Install dependencies
uv sync
```

### 3. Configuration

Create a `.env` file in the project root:

```bash
# Required: At least one LLM API key
OPENAI_API_KEY=your_openai_key_here
# OR
ANTHROPIC_API_KEY=your_anthropic_key_here

# Optional: GitHub token for private repos and higher rate limits
GITHUB_TOKEN=your_github_token_here

# Optional: Sentry integration for error tracking
SENTRY_AUTH_TOKEN=your_sentry_auth_token_here
SENTRY_ORG_SLUG=your_organization_slug
```

### 4. Create Repository List

Create a text file listing GitHub repositories to analyze (one per line):

```text
# repos.txt
https://github.com/pallets/flask
https://github.com/gin-gonic/gin
https://github.com/laravel/laravel
```

### 5. Run Analysis

```bash
# Basic usage
uv run main.py --repo-list-file repos.txt

# With all options
uv run main.py \
    --repo-list-file repos.txt \
    --output-dir ./reports \
    --format both \
    --llm "openai/gpt-5-mini" \
    --verbose
```

### 6. View Reports

Reports are generated in the `./reports` directory:
- `executive_summary.html` - Cross-project overview for management
- `{project}_report.html` - Detailed individual project reports
- PDF versions (if `--format pdf` or `--format both`)
- `report.json` - Machine-readable bundle (when using `--machine`)

## Command Line Options

```bash
uv run main.py --help
```

| Option | Description | Default |
|--------|-------------|---------|
| `--repo-list-file` | Path to file with repository URLs | **Required** |
| `--output-dir` | Output directory for reports | `./reports` |
| `--format` | Report format: `html`, `pdf`, or `both` | `both` |
| `--llm` | LLM model for summaries | `openai/gpt-5-mini` |
| `--verbose` | Enable detailed logging | `false` |
| `--env-file` | Custom .env file path | `.env` |
| `--machine` | Also write machine-readable JSON (`report.json`) | `false` |

## Configuration Details

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | One of OpenAI/Anthropic | OpenAI API key for LLM summaries |
| `ANTHROPIC_API_KEY` | One of OpenAI/Anthropic | Anthropic API key for LLM summaries |
| `GITHUB_TOKEN` | Optional | GitHub token for private repos/higher limits |
| `SENTRY_AUTH_TOKEN` | Optional | Sentry API token for error tracking |
| `SENTRY_ORG_SLUG` | Optional | Sentry organization slug |
| `PIE_SMALL_SLICE_THRESHOLD` | Optional | Fraction (0..1) to group small slices as “Others” in the Development Performance pie. Default: `0.05`. Example: `0.1`. |

### Supported LLM Models

The tool uses LiteLLM, supporting models from:
- OpenAI
- Anthropic
- **Many others**: See [LiteLLM docs](https://docs.litellm.ai/docs/providers)

### Sentry Setup

1. **Get Auth Token**: Go to Sentry → Settings → Account → API → Auth Tokens
2. **Find Org Slug**: Your organization slug from the Sentry URL: `https://sentry.io/organizations/{org-slug}/`
3. **Project Matching**: The tool automatically matches GitHub repos to Sentry projects using smart matching

#### How Project Matching Works

The tool uses a **3-strategy matching system** to connect your GitHub repositories to Sentry projects:

**Strategy 1: Exact Match**
- Looks for Sentry projects with exactly the same name as your GitHub repo
- Example: `my-app` (GitHub) → `my-app` (Sentry)

**Strategy 2: Fuzzy Matching** ⭐ *Most Common*
- Finds projects where names contain each other (substring matching)
- Example: `assessments-2` (GitHub) → `assessments` (Sentry) 
- Example: `frontend-app` (GitHub) → `company-frontend-app` (Sentry)

**Strategy 3: Advanced Matching**
- Checks project slugs and team names for repository owner/name patterns
- Example: `user-service` (GitHub) → Team: "user-team" (Sentry)

**No Perfect Names Required!** The system is designed to work with real-world naming conventions where your GitHub repo and Sentry project names might not match exactly. Just keep them reasonably similar and the tool will find the connections automatically.

### SCC Setup (Optional)

Code metrics and COCOMO estimates require the **SCC (Source Code Counter)** tool:

1. **Install SCC**: Visit [github.com/boyter/scc](https://github.com/boyter/scc) for installation instructions
2. **Verify Installation**: Run `scc --version` to confirm it's available
3. **Automatic Detection**: The tool will automatically use SCC if available

#### What SCC Provides
- **Code Metrics**: Lines of code, complexity analysis, file counts
- **Language Breakdown**: Detailed metrics for each programming language
- **COCOMO Estimates**: Development cost, timeline, and team size projections
- **Portfolio Totals**: Cross-project code metrics in executive summary

#### Without SCC
If SCC is not installed, the tool will:
- ✅ Generate all other reports normally (dependencies, security, GitHub, Sentry)
- ℹ️ Show "SCC Tool Not Available" messages in code metrics sections
- 📖 Include installation instructions in the generated reports

### Local Context (Optional)

Customize executive summaries with organizational context by creating a `local_context.txt` file in your project root:

```text
# local_context.txt
MegaCorp.com: Dedicated B2B software for the automotive industry
Team: 12 developers across 3 teams - Backend, Frontend, Mobile
Upcoming projects: Engine monitoring system, Vehicle tracking system
Report Focus: A broad idea of the health of the development team and their projects
```

#### What Local Context Provides
- **Tailored summaries**: LLM generates summaries relevant to your organization
- **Strategic context**: Incorporates team size, upcoming projects, and institutional focus
- **Stakeholder relevance**: Makes reports more meaningful for your specific audience
- **Optional feature**: Works seamlessly with or without the context file

#### Example Context Elements
- Organization name and type
- Team size and structure
- Upcoming projects or initiatives
- Key stakeholders or user base
- Strategic priorities
- Compliance requirements
- Budget constraints or opportunities

Copy `local_context.example.txt` to `local_context.txt` and customize for your organization.

## Report Structure

### Executive Summary
- **KPI Dashboard**: Key metrics across all projects
- **AI Analysis**: LLM-generated strategic insights  
- **Risk Assessment**: Security and error tracking overview
- **Technology Breakdown**: Languages, frameworks, licenses

### Individual Project Reports  
- **Project Overview**: Stars, forks, activity metrics
- **Technology Stack**: Languages, frameworks, versions
- **Code Metrics**: Lines of code, complexity, COCOMO estimates (if SCC available)
- **Dependencies**: Package analysis with security scanning
- **GitHub Activity**: Recent commits, issues, contributors
- **Sentry Errors**: Production error tracking (if configured)
- **Security Alerts**: Highlighted vulnerabilities

## Troubleshooting

### Common Issues

**"No matching Sentry projects found"**
- Check that `SENTRY_ORG_SLUG` matches your organization
- Verify repository names match Sentry project names
- The tool uses fuzzy matching - try variations

**"Rate limit exceeded"**
- Set `GITHUB_TOKEN` for higher GitHub API limits
- The tool respects rate limits automatically

**"LLM generation failed"**  
- Verify API keys are correct
- Check model name format (e.g., `openai/gpt-4`)
- Reports still generate without LLM summaries

**"SCC Tool Not Available"**
- Install SCC from [github.com/boyter/scc](https://github.com/boyter/scc)
- Verify with `scc --version`
- Reports generate normally without code metrics

### Debug Mode

Run with `--verbose` for detailed logging:

```bash
uv run main.py --repo-list-file repos.txt --verbose
```

## Development

### Project Structure

```
code_reporter/
├── cli.py              # Command line interface  
├── repo_manager.py     # Git repository management
├── language_detector.py # Language/framework detection
├── dependency_analyzer.py # Package and CVE analysis  
├── github_analyzer.py  # GitHub API integration
├── sentry_analyzer.py  # Sentry API integration (NEW!)
├── llm_analyzer.py     # LLM summary generation
├── report_generator.py # HTML/PDF report creation
└── templates/          # Jinja2 report templates
```

### Adding New Languages

1. Add detection logic in `language_detector.py`
2. Add dependency parsing in `dependency_analyzer.py`  
3. Update report templates if needed

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

[MIT](LICENSE)

## Automated Monthly Reports (GitHub Action)

Set up automated monthly reporting with GitHub Actions! The workflow runs on the 1st of every month and generates all reports automatically.

### Quick Setup:
1. Copy `.github/workflows/monthly-reports.yml` to your repository
2. Configure repository secrets (API keys, repository list)
3. Monthly reports will be generated automatically as workflow artifacts

📖 **[Complete GitHub Action Setup Guide](GITHUB_ACTION_SETUP.md)**

### Benefits:
- 📅 **Automated scheduling** - Runs monthly without manual intervention
- 🔒 **Secure configuration** - Repository URLs and API keys stored as secrets
- 📊 **Management-ready artifacts** - Combined reports perfect for stakeholders
- 🎨 **University branding** - Professional reports with official UofG colors

## Support

For issues and feature requests, please use the GitHub issue tracker.
