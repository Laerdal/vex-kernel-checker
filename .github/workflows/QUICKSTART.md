# Quick Start: Deptracker Integration

This is a quick reference guide for using the Deptracker VEX Analysis workflow.

## Initial Setup (One-Time)

### 1. Configure Secrets
In GitHub: `Settings → Secrets and variables → Actions → Secrets`

```bash
# Add these secrets:
NVD_API_KEY         # Get from https://nvd.nist.gov/developers/request-an-api-key
DEPTRACKER_TOKEN    # Your deptracker authentication token
UPLOAD_TOKEN        # Token for uploading results (if different from DEPTRACKER_TOKEN)
```

### 2. Configure Variables
In GitHub: `Settings → Secrets and variables → Actions → Variables`

```bash
# Add this variable:
DEPTRACKER_URL      # https://your-deptracker-instance.com/api/vex/latest
```

## Running the Workflow

### Option 1: Manual Run (GitHub UI)

1. Go to **Actions** tab
2. Select **"Deptracker VEX Analysis"**
3. Click **"Run workflow"**
4. Fill in the form:
   - **deptracker_url**: URL to fetch VEX file
   - **upload_enabled**: Check to upload results back
   - **verbose**: Check for detailed logs
5. Click **"Run workflow"**

### Option 2: Scheduled (Automatic)

The workflow runs automatically every Monday at 2 AM UTC.

To change schedule, edit `.github/workflows/deptracker-analysis.yml`:

```yaml
schedule:
  - cron: '0 2 * * 1'  # Every Monday at 2 AM UTC
```

### Option 3: Triggered by Another Workflow

```yaml
jobs:
  analyze:
    uses: ./.github/workflows/deptracker-analysis.yml
    with:
      deptracker_url: 'https://deptracker.example.com/api/vex/latest'
      upload_enabled: true
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      DEPTRACKER_TOKEN: ${{ secrets.DEPTRACKER_TOKEN }}
```

## Common Use Cases

### Test Run (No Upload)
```
deptracker_url:    https://deptracker.example.com/api/vex/test-project
upload_enabled:    false
verbose:           true
```

### Production Run with Upload
```
deptracker_url:    https://deptracker.example.com/api/vex/prod-project
upload_enabled:    true
upload_url:        https://deptracker.example.com/api/vex/upload/prod-project
verbose:           false
```

### Re-analyze All CVEs
```
deptracker_url:    https://deptracker.example.com/api/vex/project-123
reanalyse:         true
upload_enabled:    true
```

## Viewing Results

### Workflow Results
1. Go to **Actions** tab
2. Click on the workflow run
3. View **job summary** for quick stats
4. Click **"analyze-vex"** job for detailed logs

### Download Artifacts
1. Scroll to bottom of workflow run page
2. Under **Artifacts**, download:
   - `vex-analysis-results-XXXXX.zip`
3. Extract to view:
   - `analyzed-vex.json` - Full analysis results
   - `analyzed-vex-report.md` - Human-readable report
   - `input-vex.json` - Original VEX file
   - `kernel.config` - Kernel configuration used

## Troubleshooting

### "VEX file download failed"
- Check `deptracker_url` is correct
- Verify `DEPTRACKER_TOKEN` is set
- Ensure URL is accessible from GitHub Actions

### "Analysis completed with 0 CVEs"
- Verify VEX file format is correct
- Check if vulnerabilities are kernel-related
- Use `--analyze-all-cves` if needed

### "Upload failed"
- Verify `upload_url` is correct
- Check `UPLOAD_TOKEN` has write permissions
- Ensure upload endpoint accepts JSON POST

## Need Help?

- **Full Documentation**: [DEPTRACKER_SETUP.md](./DEPTRACKER_SETUP.md)
- **Workflow Details**: [README.md](./README.md)
- **Main Project**: [../../README.md](../../README.md)
- **Issues**: [GitHub Issues](https://github.com/Laerdal/vex-kernel-checker/issues)
