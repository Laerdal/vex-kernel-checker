# AI Assistant Demo

This directory contains examples showing how to use the AI Assistant features in vex-kernel-checker.

## Quick Start

1. **Install AI dependencies:**
   ```bash
   pip install vex-kernel-checker[ai]
   ```

2. **Set up API key:**
   ```bash
   # For OpenAI
   export OPENAI_API_KEY='your-key-here'
   
   # OR for Anthropic
   export ANTHROPIC_API_KEY='your-key-here'
   ```

3. **Run the demo:**
   ```bash
   python3 examples/ai_demo.py
   ```

## What the Demo Shows

The demo (`ai_demo.py`) demonstrates three AI capabilities:

### 1. CVE Relevance Detection
Analyzes whether a CVE affects your specific kernel configuration:
- Input: CVE description + kernel config options
- Output: Relevance verdict, confidence score, reasoning

### 2. Mitigation Suggestions
Provides security recommendations for vulnerabilities:
- Input: CVE details + current configuration
- Output: Recommended actions, config changes, workarounds

### 3. Batch Analysis
Processes multiple CVEs efficiently:
- Input: List of CVEs with configurations
- Output: Bulk analysis results with rate limiting

## Using with vex-kernel-checker CLI

Add AI analysis to your normal workflow:

```bash
# Basic AI-enabled analysis
./vex-kernel-checker.py \
    --sbom test.json \
    --kernel-config /boot/config \
    --ai-enabled \
    --ai-api-key $OPENAI_API_KEY

# Use specific model
./vex-kernel-checker.py \
    --sbom test.json \
    --kernel-config /boot/config \
    --ai-enabled \
    --ai-provider anthropic \
    --ai-model claude-3-opus-20240229 \
    --ai-api-key $ANTHROPIC_API_KEY

# AI analysis with custom output
./vex-kernel-checker.py \
    --sbom test.json \
    --kernel-config /boot/config \
    --ai-enabled \
    --output ai-enhanced-results.json
```

## Cost Considerations

AI API calls incur costs based on token usage:

- **GPT-3.5-Turbo**: ~$0.001/analysis (fast, good for bulk)
- **GPT-4**: ~$0.03/analysis (best quality)
- **Claude-3-Haiku**: ~$0.0005/analysis (fastest)
- **Claude-3-Opus**: ~$0.05/analysis (highest quality)

A typical CVE analysis uses 500-2000 tokens.

## Troubleshooting

**Missing Libraries Error:**
```bash
pip install openai anthropic
```

**API Key Error:**
```bash
# Check your key is set
echo $OPENAI_API_KEY
```

**Rate Limit Error:**
- Increase `rate_limit_delay` in AIAssistant constructor
- Use a less expensive model for batch operations

## More Information

See [docs/AI_ASSISTANT.md](../docs/AI_ASSISTANT.md) for complete documentation.
