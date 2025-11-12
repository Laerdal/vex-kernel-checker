# GitHub Actions Workflows

This directory contains GitHub Actions workflows for the VEX Kernel Checker project.

## Available Workflows

### 1. CI Workflow (`ci.yml`)

Continuous Integration workflow that runs on every push and pull request:
- **Test**: Runs unit tests across multiple Python versions
- **Lint**: Code quality checks with flake8 and black
- **Performance**: Benchmarks on main branch
- **Integration**: End-to-end functionality tests

### 2. VEX Analysis Workflow (`vex-analysis.yml`)

Automated VEX file analysis workflow that integrates with deptracker or similar dependency tracking systems.

#### Features

- ✅ Fetch VEX/CycloneDX files from remote sources (deptracker, etc.)
- ✅ Analyze vulnerabilities against kernel configurations
- ✅ Automated Edge WebDriver setup for enhanced patch checking
- ✅ Flexible kernel branch/tag selection
- ✅ Upload completed analysis back to source (optional)
- ✅ Scheduled or manual execution
- ✅ Detailed reporting and artifacts
- ✅ PR comments with analysis results
- ✅ Secure command execution (injection-safe)
- ✅ 60-minute timeout protection

#### Trigger Methods

**1. Manual Workflow Dispatch**

Run manually from GitHub Actions UI with custom parameters:

```yaml
Inputs:
  - vex_url: URL to fetch VEX file from deptracker endpoint
  - kernel_config_url: URL to fetch kernel config file (required)
  - kernel_source_git_url: Git URL to fetch kernel source (required)
  - kernel_branch: Kernel branch/tag to checkout (optional, e.g., v6.1, linux-6.1.y)
  - upload_enabled: Upload results back (true/false)
  - upload_url: URL to upload completed analysis (required if upload_enabled)
  - reanalyse: Re-analyze existing CVEs (true/false)
  - verbose: Enable verbose output (true/false)
```

**2. Scheduled Execution**

Runs automatically every Monday at 2 AM UTC:

```yaml
schedule:
  - cron: '0 2 * * 1'  # Weekly on Monday
```

**3. Workflow Call (from other workflows)**

Can be called by other workflows:

```yaml
jobs:
  analyze:
    uses: ./.github/workflows/vex-analysis.yml
    with:
      vex_url: 'https://deptracker.example.com/api/vex/latest'
      kernel_config_url: 'https://example.com/kernel-configs/6.1.config'
      kernel_source_git_url: 'https://github.com/torvalds/linux.git'
      kernel_branch: 'v6.1'
      upload_enabled: true
      upload_url: 'https://deptracker.example.com/api/vex/upload'
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      VEX_API_TOKEN: ${{ secrets.VEX_API_TOKEN }}
```

#### Configuration

##### Required Secrets

Set these in your GitHub repository settings (Settings → Secrets and variables → Actions):

| Secret | Description | Required |
|--------|-------------|----------|
| `NVD_API_KEY` | NVD API key for CVE data and patch checking | Optional (enables full analysis mode) |
| `VEX_API_TOKEN` | Authentication token for deptracker (fetch and upload) | If deptracker requires auth |

**Note**: `VEX_API_TOKEN` is used for both fetching and uploading to deptracker. If no token is provided, the workflow attempts unauthenticated access.

##### Repository Variables

Set these in Settings → Secrets and variables → Actions → Variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `vex_url` | Default URL for fetching VEX files | `https://deptracker.example.com/api/vex` |

**Note**: Repository variables provide defaults that can be overridden via workflow inputs.

#### Usage Examples

##### Example 1: Manual Analysis with Custom URLs

1. Go to Actions tab in GitHub
2. Select "VEX Analysis" workflow
3. Click "Run workflow"
4. Fill in parameters:
   - `vex_url`: `https://your-deptracker.com/api/vex/project123`
   - `kernel_config_url`: `https://your-server.com/configs/prod.config`
   - `kernel_source_git_url`: `https://github.com/torvalds/linux.git`
   - `kernel_branch`: `v6.1` (or leave empty for default branch)
   - `upload_enabled`: `false`
   - `verbose`: `true`
5. Click "Run workflow"

##### Example 2: Automated Analysis with Upload

Set up repository variables:
- `vex_url`: `https://deptracker.example.com/api/vex`

Set up secrets:
- `NVD_API_KEY`: Your NVD API key
- `VEX_API_TOKEN`: Your deptracker authentication token

The workflow will run weekly and:
1. Fetch VEX file from deptracker
2. Install Microsoft Edge and EdgeDriver for patch checking
3. Clone kernel source (specify branch in workflow inputs)
4. Analyze vulnerabilities with full patch verification
5. Generate detailed reports
6. Store artifacts for 30 days

##### Example 3: Integration in CI/CD Pipeline

```yaml
name: Full Security Pipeline

on:
  push:
    branches: [ main ]

jobs:
  # Your build jobs here

  security-analysis:
    needs: build
    uses: ./.github/workflows/vex-analysis.yml
    with:
      vex_url: 'https://deptracker.company.com/api/vex/${{ github.sha }}'
      kernel_config_url: 'https://configs.company.com/production.config'
      kernel_source_git_url: 'https://github.com/torvalds/linux.git'
      kernel_branch: 'v6.1'
      upload_enabled: true
      upload_url: 'https://deptracker.company.com/api/results/${{ github.sha }}'
      verbose: true
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      VEX_API_TOKEN: ${{ secrets.VEX_API_TOKEN }}
```

#### Workflow Steps Explained

1. **Checkout**: Clones the vex-kernel-checker repository
2. **Setup Python**: Installs Python 3.9 and dependencies
3. **Setup Edge WebDriver**: Installs Microsoft Edge and EdgeDriver for patch checking
4. **Fetch VEX**: Downloads VEX file from deptracker (with auth if provided)
5. **Fetch Kernel Config**: Downloads kernel configuration from specified URL
6. **Setup Kernel Source**: Clones kernel source with sparse checkout (specific branch/tag if specified)
7. **Run Analysis**: Executes vex-kernel-checker with secure command array (injection-safe)
8. **Generate Summary**: Creates summary statistics for the workflow
9. **Upload Results**: Optionally uploads completed analysis back to deptracker
10. **Upload Artifacts**: Stores all analysis files for 30 days
11. **PR Comment**: Posts analysis results on pull requests (if applicable)

**Timeout**: The entire workflow has a 60-minute timeout to prevent hanging jobs.

#### Outputs and Artifacts

The workflow produces the following artifacts:

- `input-vex.json` - Original VEX file from deptracker
- `analyzed-vex.json` - Completed analysis with vulnerability states
- `analyzed-vex-report.md` - Human-readable markdown report
- `kernel.config` - Kernel configuration used for analysis

Access artifacts from the workflow run page for 30 days.

#### Advanced Configuration

##### Kernel Branch Selection

The workflow supports flexible kernel branch/tag selection:

```yaml
# Use a specific kernel version tag
kernel_source_git_url: 'https://github.com/torvalds/linux.git'
kernel_branch: 'v6.1'

# Use a stable branch
kernel_source_git_url: 'https://github.com/torvalds/linux.git'
kernel_branch: 'linux-6.1.y'

# Use vendor-specific kernel
kernel_source_git_url: 'https://github.com/vendor/linux-vendor.git'
kernel_branch: 'vendor-v4.19'

# Use default branch (leave kernel_branch empty)
kernel_source_git_url: 'https://github.com/torvalds/linux.git'
```

The workflow uses sparse checkout to only fetch essential files (Makefile, Kconfig files) for faster cloning.

##### Analysis Modes

The workflow automatically adjusts based on available secrets:

**Config-only mode** (no NVD API key):
- Only checks kernel configuration
- No CVE details or patch verification
- Fast execution

**Full analysis mode** (with NVD API key):
- Fetches CVE details from NVD
- Performs patch checking with Edge WebDriver
- Complete vulnerability analysis

**Enhanced patch checking** (NVD API key + Edge WebDriver):
- Uses Selenium to fetch patches from complex websites
- Handles JavaScript-heavy sources
- Better success rate for patch verification

##### Integration with Other Services

The workflow can be adapted to work with various systems:

**Jira/GitHub Issues Integration:**
```yaml
- name: Create issues for exploitable CVEs
  run: |
    # Parse analyzed-vex.json and create issues for exploitable CVEs
    # using GitHub CLI or Jira API
```

**Slack/Teams Notifications:**
```yaml
- name: Send notification
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "VEX analysis completed with ${{ steps.summary.outputs.exploitable }} exploitable CVEs"
      }
```

**S3/Blob Storage:**
```yaml
- name: Upload to S3
  uses: aws-actions/configure-aws-credentials@v4
  # ... upload analyzed files to S3
```

#### Troubleshooting

##### VEX File Download Fails

- Check `vex_url` is correct and accessible
- Verify `VEX_API_TOKEN` is set if authentication is required
- Ensure URL returns valid JSON (use `curl --fail` to test)
- Check network connectivity and firewall rules

##### Kernel Source Clone Fails

- Verify `kernel_source_git_url` is a valid Git repository
- Check if `kernel_branch` exists in the repository
- Ensure repository is publicly accessible or credentials are provided
- Try without `kernel_branch` to use default branch

##### Edge WebDriver Setup Fails

- Check Microsoft Edge installation logs
- Verify EdgeDriver version matches installed Edge version
- Ensure sufficient disk space for download and installation
- Check internet connectivity to Microsoft CDN

##### Analysis Fails

- Ensure kernel config file is valid and accessible
- Check if NVD API key is valid (if provided)
- Review analysis logs for specific errors
- Verify Edge WebDriver is accessible at `/usr/local/bin/msedgedriver`
- Check timeout (60 minutes) - large analyses may need more time

##### Upload Fails

- Verify `upload_url` is correct and accessible
- Ensure `VEX_API_TOKEN` has write permissions
- Check the upload endpoint accepts JSON POST requests
- Review HTTP status codes in logs
- Confirm analyzed-vex.json was created successfully

##### No Vulnerabilities Analyzed

- Check if VEX file contains vulnerabilities
- Verify VEX file format is correct (CycloneDX or VEX format)
- Ensure vulnerabilities are kernel-related (or use `--analyze-all-cves`)

#### Best Practices

1. **Use NVD API Key**: Significantly improves analysis accuracy with patch checking and CVE details
2. **Specify Kernel Branch**: Always specify `kernel_branch` to ensure reproducible analyses
3. **Single Token**: Use `VEX_API_TOKEN` for both fetch and upload operations
4. **Enable Verbose Mode**: Helpful for debugging and understanding the analysis
5. **Review Artifacts**: Always check the generated reports and analyzed VEX files
6. **Secure Secrets**: Never commit API keys or tokens to the repository
7. **Monitor Workflow Runs**: Set up notifications for failed workflows
8. **Version Control**: Tag or commit-pin the workflow for production use
9. **Test First**: Run manually with `upload_enabled: false` before enabling uploads
10. **Timeout Awareness**: Large repositories or many CVEs may approach the 60-minute timeout

#### Security Considerations

- **API Keys**: Store all API keys in GitHub Secrets, never in code
- **Single Token**: `VEX_API_TOKEN` used for both fetch and upload reduces secret sprawl
- **Validation**: The workflow validates downloaded files before processing with `--fail` flag
- **Command Injection**: Uses bash arrays to prevent command injection attacks
- **Isolation**: Each workflow run uses a fresh Ubuntu environment
- **Artifacts**: Sensitive data in artifacts expires after 30 days
- **HTTPS Only**: All network requests use HTTPS with `curl --fail`
- **Timeout Protection**: 60-minute timeout prevents runaway jobs
- **File Validation**: All downloaded files are checked for existence and non-zero size

#### Contributing

To improve this workflow:
1. Test changes on a fork first
2. Document any new inputs or secrets
3. Update this README with usage examples
4. Consider backward compatibility
5. Add appropriate error handling

#### Support

For issues or questions:
- GitHub Issues: [vex-kernel-checker/issues](https://github.com/Laerdal/vex-kernel-checker/issues)
- Documentation: See main [README.md](../../README.md)
- Workflow Syntax: [GitHub Actions Documentation](https://docs.github.com/en/actions)

## Maintenance

The workflows are maintained as part of the VEX Kernel Checker project. Updates to GitHub Actions or Python versions may require workflow updates.

Last updated: November 2025
