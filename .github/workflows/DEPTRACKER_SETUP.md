# Deptracker Integration - Configuration Example

This document provides configuration examples for integrating VEX Kernel Checker with deptracker.

## GitHub Repository Configuration

### 1. Set Up Repository Secrets

Navigate to: `Settings → Secrets and variables → Actions → Secrets`

Add the following secrets:

```
NVD_API_KEY=your-nvd-api-key-here
DEPTRACKER_TOKEN=your-deptracker-authentication-token
UPLOAD_TOKEN=your-upload-authentication-token
```

### 2. Set Up Repository Variables

Navigate to: `Settings → Secrets and variables → Actions → Variables`

Add the following variables:

```
DEPTRACKER_URL=https://your-deptracker-instance.com/api/vex/latest
```

## Deptracker API Integration

### Expected API Endpoints

#### 1. Fetch VEX File (GET)

```
GET https://your-deptracker-instance.com/api/vex/{project-id}
Headers:
  Authorization: Bearer <DEPTRACKER_TOKEN>
  Accept: application/json

Response: CycloneDX VEX JSON file
```

Example response structure:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2023-1234",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
      },
      "ratings": [
        {
          "severity": "high",
          "method": "CVSSv3"
        }
      ],
      "description": "Vulnerability description...",
      "analysis": {
        "state": "in_triage"
      }
    }
  ]
}
```

#### 2. Upload Analyzed VEX File (POST)

```
POST https://your-deptracker-instance.com/api/vex/upload
Headers:
  Authorization: Bearer <UPLOAD_TOKEN>
  Content-Type: application/json

Body: Analyzed CycloneDX VEX JSON file with completed analysis

Response:
{
  "status": "success",
  "message": "Analysis uploaded successfully",
  "id": "analysis-12345"
}
```

## Manual Workflow Execution

### Example 1: Analyze Specific Project

1. Go to GitHub Actions tab
2. Select "Deptracker VEX Analysis"
3. Click "Run workflow"
4. Fill in:
```
deptracker_url: https://deptracker.example.com/api/vex/project-123
kernel_config_url: https://your-server.com/configs/production.config
upload_enabled: true
upload_url: https://deptracker.example.com/api/vex/upload/project-123
reanalyse: false
verbose: true
```

### Example 2: Test Run (No Upload)

```
deptracker_url: https://deptracker.example.com/api/vex/test-project
kernel_config_url: (leave empty to use default)
upload_enabled: false
upload_url: (leave empty)
reanalyse: false
verbose: true
```

### Example 3: Re-analyze All CVEs

```
deptracker_url: https://deptracker.example.com/api/vex/project-456
kernel_config_url: https://your-server.com/configs/custom.config
upload_enabled: true
upload_url: https://deptracker.example.com/api/vex/upload/project-456
reanalyse: true
verbose: true
```

## Scheduled Workflow Configuration

### Modify Schedule

Edit `.github/workflows/deptracker-analysis.yml`:

```yaml
schedule:
  # Run daily at 3 AM UTC
  - cron: '0 3 * * *'
  
  # Run every 6 hours
  # - cron: '0 */6 * * *'
  
  # Run weekly on Monday at 2 AM UTC
  # - cron: '0 2 * * 1'
```

### Configure Default Behavior

For scheduled runs, the workflow uses:
- `deptracker_url`: From `DEPTRACKER_URL` repository variable
- `kernel_config_url`: System default or example config
- `upload_enabled`: false (for safety)
- `verbose`: true

To enable upload for scheduled runs, modify the workflow default:

```yaml
upload_enabled:
  description: 'Upload completed analysis'
  required: false
  type: boolean
  default: true  # Changed from false
```

## Workflow Call from Other Workflows

### Example: Security Pipeline

Create `.github/workflows/security-pipeline.yml`:

```yaml
name: Security Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Your build steps here
  
  vex-analysis:
    needs: build
    uses: ./.github/workflows/deptracker-analysis.yml
    with:
      deptracker_url: 'https://deptracker.example.com/api/vex/latest'
      upload_enabled: true
      upload_url: 'https://deptracker.example.com/api/vex/upload'
      verbose: false
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      DEPTRACKER_TOKEN: ${{ secrets.DEPTRACKER_TOKEN }}
      UPLOAD_TOKEN: ${{ secrets.UPLOAD_TOKEN }}
```

### Example: Multi-Project Analysis

```yaml
name: Multi-Project VEX Analysis

on:
  schedule:
    - cron: '0 4 * * *'  # Daily at 4 AM

jobs:
  analyze-project-a:
    uses: ./.github/workflows/deptracker-analysis.yml
    with:
      deptracker_url: 'https://deptracker.example.com/api/vex/project-a'
      upload_enabled: true
      upload_url: 'https://deptracker.example.com/api/vex/upload/project-a'
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      DEPTRACKER_TOKEN: ${{ secrets.DEPTRACKER_TOKEN }}
  
  analyze-project-b:
    uses: ./.github/workflows/deptracker-analysis.yml
    with:
      deptracker_url: 'https://deptracker.example.com/api/vex/project-b'
      upload_enabled: true
      upload_url: 'https://deptracker.example.com/api/vex/upload/project-b'
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      DEPTRACKER_TOKEN: ${{ secrets.DEPTRACKER_TOKEN }}
```

## Local Testing

Test the workflow components locally before deploying:

```bash
# 1. Fetch VEX file
curl -H "Authorization: Bearer $DEPTRACKER_TOKEN" \
     https://deptracker.example.com/api/vex/test-project \
     -o test-vex.json

# 2. Run analysis locally
python3 vex-kernel-checker.py \
  --vex-file test-vex.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /usr/src/linux \
  --output analyzed-vex.json \
  --api-key "$NVD_API_KEY" \
  --verbose

# 3. Test upload (dry run)
curl -X POST \
     -H "Authorization: Bearer $UPLOAD_TOKEN" \
     -H "Content-Type: application/json" \
     -d @analyzed-vex.json \
     https://deptracker.example.com/api/vex/upload/test-project

# 4. Verify results
cat analyzed-vex.json | jq '.vulnerabilities[] | {id, state: .analysis.state}'
```

## Monitoring and Notifications

### View Workflow Runs

- Go to repository → Actions tab
- Select "Deptracker VEX Analysis"
- View run history, logs, and artifacts

### Set Up Email Notifications

GitHub automatically sends emails for:
- Failed workflow runs
- First failed run after a success

Configure in: `Settings → Notifications → Actions`

### Custom Notifications (Slack Example)

Add to workflow:

```yaml
- name: Notify Slack
  if: always()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {
        "text": "VEX Analysis: ${{ job.status }}",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*VEX Analysis Results*\nStatus: ${{ job.status }}\nVulnerabilities: ${{ steps.fetch-vex.outputs.vuln_count }}"
            }
          }
        ]
      }
```

## Troubleshooting

### Authentication Issues

```bash
# Test deptracker authentication
curl -v -H "Authorization: Bearer $DEPTRACKER_TOKEN" \
     https://deptracker.example.com/api/vex/test

# Expected: HTTP 200 OK
# If 401: Check token validity
# If 403: Check token permissions
```

### VEX File Format Issues

Ensure your VEX file follows CycloneDX 1.5 specification:
- Required fields: `bomFormat`, `specVersion`, `version`, `vulnerabilities`
- Each vulnerability should have `id` and optionally `analysis`

### Upload Failures

Check upload endpoint requirements:
- Accepts `POST` method
- Accepts `application/json` content type
- Returns success status (200-299)
- Authentication token has write permissions

### Workflow Permission Issues

Ensure workflow has necessary permissions in `.github/workflows/deptracker-analysis.yml`:

```yaml
permissions:
  contents: read
  pull-requests: write  # For PR comments
  actions: read
```

## Best Practices

1. **Start with Manual Runs**: Test manually before enabling scheduled runs
2. **Use Separate Tokens**: Different tokens for fetch and upload operations
3. **Enable Upload Gradually**: Test without upload first
4. **Monitor Costs**: NVD API calls and GitHub Actions minutes
5. **Rotate Tokens**: Regularly rotate authentication tokens
6. **Version Control**: Track workflow changes in git
7. **Document Changes**: Update this file when modifying workflows
8. **Test Failures**: Intentionally test failure scenarios
9. **Backup Results**: Store important artifacts externally
10. **Review Regularly**: Periodically review workflow logs and results

## Support

For help with:
- **VEX Kernel Checker**: See main [README.md](../../README.md)
- **GitHub Actions**: [GitHub Actions Documentation](https://docs.github.com/en/actions)
- **Deptracker Integration**: Contact your deptracker administrator
- **Issues**: [GitHub Issues](https://github.com/Laerdal/vex-kernel-checker/issues)
