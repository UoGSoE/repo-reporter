# 📅 Monthly GitHub Action Setup

This guide explains how to set up the automated monthly reporting GitHub Action that generates Code Reporter analysis on the 1st of every month.

## 🚀 Quick Setup

### 1. Repository Secrets Configuration

Go to your repository **Settings → Secrets and variables → Actions** and add the following secrets:

#### **Required Secrets:**

| Secret Name | Description | Example/Notes |
|-------------|-------------|---------------|
| `REPO_LIST` | List of GitHub repository URLs to analyze (one per line) | See format below |
| `OPENAI_API_KEY` | OpenAI API key for LLM summaries | Get from [OpenAI Platform](https://platform.openai.com/api-keys) |
| `GITHUB_TOKEN` | Already exists by default | Used for private repo access |

#### **Optional Secrets:**

| Secret Name | Description | When to Use |
|-------------|-------------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key (alternative to OpenAI) | If you prefer Claude models |
| `SENTRY_AUTH_TOKEN` | Sentry API authentication token | For error tracking integration |
| `SENTRY_ORG_SLUG` | Your Sentry organization slug | Required if using Sentry |

### 2. Repository List Format

The `REPO_LIST` secret should contain repository URLs, one per line:

```text
https://github.com/UoGSoE/assessments-2
https://github.com/UoGSoE/another-project
https://github.com/your-org/private-repo
https://github.com/your-org/public-repo
```

**Benefits of using a secret:**
- ✅ Private repository URLs remain confidential
- ✅ Easy to update without code changes  
- ✅ No sensitive information in version control

### 3. Workflow Schedule

The action runs automatically:
- **📅 When**: 1st of every month at 6:00 AM UTC
- **⏱️ Duration**: Typically 5-15 minutes depending on repository count
- **🔄 Manual Trigger**: Available via GitHub Actions tab

## 📊 Generated Artifacts

Each run produces **4 downloadable artifacts** (retained for 90 days):

### **🎯 For Management:**
- **`monthly-combined-report-{run-number}`** - Complete overview with navigation index
- **`monthly-executive-summary-{run-number}`** - KPI dashboard and strategic insights

### **👩‍💻 For Technical Teams:**  
- **`monthly-individual-reports-{run-number}`** - Detailed per-project analysis
- **`monthly-reports-complete-{run-number}`** - All reports in one package

## 🔧 Advanced Configuration

### Custom LLM Models

You can manually trigger the workflow with different LLM models:

1. Go to **Actions → Monthly Code Analysis Reports**
2. Click **"Run workflow"**
3. Enter your preferred model:
   - `openai/gpt-4o` (premium, detailed analysis)
   - `openai/gpt-4o-mini` (default, good balance)
   - `anthropic/claude-3-sonnet` (requires Anthropic API key)

### Private Repository Access

The workflow automatically handles private repositories using the default `GITHUB_TOKEN`. For repositories in different organizations, ensure the token has appropriate permissions.

### Sentry Integration

If you have Sentry error tracking, add these optional secrets:
- `SENTRY_AUTH_TOKEN`: Get from Sentry → Settings → Account → API → Auth Tokens
- `SENTRY_ORG_SLUG`: From your Sentry URL: `https://sentry.io/organizations/{org-slug}/`

## 📁 File Structure

The GitHub Action creates this folder structure in your repository:

```
.github/
└── workflows/
    └── monthly-reports.yml    # The main workflow file
```

## 🔍 Monitoring & Troubleshooting

### Viewing Run Results

1. Go to **Actions** tab in your repository
2. Click on **"Monthly Code Analysis Reports"**
3. Select the latest run to see:
   - ✅ Step-by-step execution logs
   - 📊 Analysis summary in the run summary
   - 📂 Downloadable report artifacts

### Common Issues & Solutions

**❌ "No matching Sentry projects found"**
- Check `SENTRY_ORG_SLUG` matches your organization
- Ensure Sentry project names are similar to GitHub repo names

**❌ "LLM generation failed"**
- Verify `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is valid
- Check API key permissions and usage limits

**❌ "Failed to clone repository"**
- Repository might be private and inaccessible
- Check repository URLs in `REPO_LIST` are correct

**❌ "Rate limit exceeded"**
- GitHub API limits reached - workflow will retry automatically
- Consider spreading analysis across multiple runs for large repo lists

### Debug Mode

To get detailed logs, view the workflow run and expand the "Run Code Reporter Analysis" step. The `--verbose` flag provides comprehensive debugging information.

## 🎨 Report Features

All generated reports include:

✅ **University of Glasgow Branding** - Official color scheme and styling  
✅ **Professional Layout** - Management-ready presentation  
✅ **Interactive Navigation** - Easy project jumping in combined report  
✅ **Comprehensive Analysis** - Security, dependencies, activity, Sentry integration  
✅ **LLM-Powered Insights** - AI-generated summaries and recommendations  

## 🔄 Updating the Workflow

To modify the schedule or add features:

1. Edit `.github/workflows/monthly-reports.yml`
2. Commit changes to the main branch
3. Next scheduled run will use the updated workflow

### Schedule Examples:

```yaml
# Every 1st of the month at 6 AM UTC (current)
- cron: '0 6 1 * *'

# Every Monday at 9 AM UTC  
- cron: '0 9 * * 1'

# 1st and 15th of every month
- cron: '0 6 1,15 * *'
```

## 🎉 Benefits

**For Management:**
- 📈 Monthly portfolio health overview
- 🚨 Automated security vulnerability alerts  
- 📊 Key performance indicators and trends
- 🎯 Zero-effort report generation

**For Technical Teams:**
- 🔍 Detailed dependency analysis
- 🛡️ Security vulnerability tracking
- 📱 Sentry error monitoring integration
- ⚡ Automated maintenance insights

**For Organization:**
- 🏛️ Consistent University branding
- 📂 Centralized report storage
- 🔒 Secure handling of private repositories
- 📅 Predictable monthly reporting cycle

---

## 🆘 Support

If you encounter issues:

1. Check the [troubleshooting section](#common-issues--solutions) above
2. Review the workflow run logs in GitHub Actions
3. Verify all required secrets are properly configured
4. Test with a manual workflow trigger first

The GitHub Action leverages the same robust Code Reporter tool you've been using locally, just automated and running in the cloud! 🚀