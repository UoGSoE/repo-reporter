# LLM Prompt Customization

The Code Reporter uses a Jinja2 template for the LLM executive summary prompt, making it easy to customize the tone, focus, and style of generated summaries.

## Template Location
The prompt template is located at: `code_reporter/templates/llm_prompt.txt`

## Available Variables
The template has access to the following data:

- `context.total_projects` - Number of analyzed projects
- `context.languages` - Dictionary of detected languages and counts
- `context.frameworks` - Dictionary of frameworks found
- `context.security_metrics` - Security vulnerability information
- `context.activity_metrics` - Development activity data
- `context.popularity_metrics` - Stars, forks, popular projects
- `context_json` - Full context data as formatted JSON

## Customization Examples

### Focus on Technical Details
```jinja2
You are writing a technical report for engineering leadership about {{ context.total_projects }} software projects.

Focus on:
- Technical debt and code quality
- Architecture patterns and best practices
- Development team productivity metrics
- Technology stack modernization opportunities

{{ context_json }}

Write a detailed technical assessment...
```

### Business Risk Assessment
```jinja2
You are conducting a business risk assessment for {{ context.total_projects }} software applications.

Prioritize:
- Security vulnerabilities and compliance risks
- Operational stability and uptime concerns
- Maintenance costs and resource allocation
- Competitive positioning

{{ context_json }}

Provide a comprehensive risk analysis...
```

### CTO Brief
```jinja2
You are preparing a quarterly CTO brief about the technology portfolio.

Cover:
- Strategic technology decisions and their impact
- Team performance and development velocity
- Innovation opportunities and competitive advantages
- Resource optimization recommendations

{{ context_json }}

Create an executive brief suitable for board presentation...
```

## Model Selection
Use the `--llm` flag to specify different models:

```bash
# Cost-effective option (default)
code-reporter --llm openai/o4-mini --repo-list-file repos.txt

# Higher quality option  
code-reporter --llm gpt-4o --repo-list-file repos.txt

# Anthropic Claude
code-reporter --llm claude-3-5-sonnet-20241022 --repo-list-file repos.txt
```

## Tips for Effective Prompts
1. **Be specific** about the audience (executives, engineers, board members)
2. **Define the format** you want (bullet points, paragraphs, sections)
3. **Set the tone** (formal, conversational, technical, business-focused)
4. **Use the context data** to make summaries data-driven and specific
5. **Test different models** to find the right balance of cost and quality