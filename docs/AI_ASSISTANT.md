# AI Assistant for VEX Kernel Checker

## Overview

The AI Assistant adds intelligent vulnerability analysis capabilities to vex-kernel-checker using Large Language Models (LLMs). It can help determine CVE relevance, suggest mitigations, and enhance analysis accuracy.

## Features

### 🔍 Intelligent CVE Relevance Detection
- Analyzes CVE descriptions to determine kernel relevance
- Considers kernel configuration and architecture
- Provides confidence scores and reasoning

### 💡 Mitigation Recommendations
- Generates actionable security recommendations
- Suggests configuration changes
- Provides patch application guidance

### 🚀 Enhanced Analysis
- Augments existing analysis with AI insights
- Flags potential conflicts for manual review
- Batch processing for multiple CVEs

## Setup

### Installation

Install the required AI provider libraries:

```bash
# For OpenAI
pip install openai

# For Anthropic
pip install anthropic

# Or both
pip install openai anthropic
```

### API Keys

Set your API key as an environment variable:

```bash
# For OpenAI
export OPENAI_API_KEY="your-api-key-here"

# For Anthropic
export ANTHROPIC_API_KEY="your-api-key-here"
```

Or pass it via command line:

```bash
python3 vex-kernel-checker.py --ai-enabled --ai-api-key "your-key"
```

## Usage

### Basic AI-Enhanced Analysis

```bash
python3 vex-kernel-checker.py \
  --vex-file vulnerabilities.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /usr/src/linux \
  --ai-enabled
```

### Specify AI Provider and Model

```bash
# Use OpenAI GPT-4
python3 vex-kernel-checker.py \
  --vex-file vulnerabilities.json \
  --kernel-config /boot/config \
  --kernel-source /usr/src/linux \
  --ai-enabled \
  --ai-provider openai \
  --ai-model gpt-4

# Use Anthropic Claude
python3 vex-kernel-checker.py \
  --vex-file vulnerabilities.json \
  --kernel-config /boot/config \
  --kernel-source /usr/src/linux \
  --ai-enabled \
  --ai-provider anthropic \
  --ai-model claude-3-opus-20240229
```

### Configuration File

Add AI settings to your config file:

**INI format** (`config.ini`):
```ini
[vex-kernel-checker]
vex_file = vulnerabilities.json
kernel_config = /boot/config
kernel_source = /usr/src/linux
ai_enabled = true
ai_provider = openai
ai_model = gpt-4
```

**JSON format** (`config.json`):
```json
{
  "vex_file": "vulnerabilities.json",
  "kernel_config": "/boot/config",
  "kernel_source": "/usr/src/linux",
  "ai_enabled": true,
  "ai_provider": "openai",
  "ai_model": "gpt-4"
}
```

## Programmatic Usage

```python
from vex_kernel_checker import AIAssistant

# Initialize AI assistant
ai = AIAssistant(
    api_key="your-api-key",
    model="gpt-4",
    provider="openai"
)

# Analyze CVE relevance
is_relevant, reasoning, confidence = ai.analyze_cve_relevance(
    cve_id="CVE-2024-1234",
    description="Linux kernel vulnerability in driver subsystem...",
    kernel_config={"CONFIG_DRIVER": True},
    architecture="x86_64"
)

print(f"Relevant: {is_relevant}")
print(f"Confidence: {confidence:.2%}")
print(f"Reasoning: {reasoning}")

# Get mitigation recommendations
recommendation = ai.suggest_mitigation(
    cve_id="CVE-2024-1234",
    description="Vulnerability description...",
    severity="HIGH",
    patch_available=True,
    config_options=["CONFIG_DRIVER", "CONFIG_SECURITY"]
)

print(f"Recommendation: {recommendation}")
```

## AI Analysis Output

The AI assistant adds an `ai_analysis` field to vulnerability records:

```json
{
  "id": "CVE-2024-1234",
  "analysis": {
    "state": "not_affected",
    "ai_analysis": {
      "is_relevant": false,
      "reasoning": "This CVE affects the XFS filesystem driver which is not enabled in this kernel configuration (CONFIG_XFS_FS=n)",
      "confidence": 0.95,
      "timestamp": "2025-11-07T14:30:00Z"
    }
  }
}
```

When AI detects a potential conflict:

```json
{
  "ai_analysis": {
    "is_relevant": true,
    "confidence": 0.92,
    "review_recommended": true,
    "conflict": "AI analysis suggests vulnerability may be relevant, but current analysis marked as not affected"
  }
}
```

## Supported Models

### OpenAI
- `gpt-4` (recommended)
- `gpt-4-turbo`
- `gpt-3.5-turbo` (faster, less accurate)

### Anthropic
- `claude-3-opus-20240229` (highest quality)
- `claude-3-sonnet-20240229` (balanced)
- `claude-3-haiku-20240307` (fastest)

## Cost Considerations

- AI analysis adds API costs per CVE analyzed
- Typical cost: $0.01-0.05 per CVE (depending on model)
- Use `--cve-id` to analyze specific CVEs during testing
- Consider using cheaper models for initial screening

## Best Practices

1. **Start with selective analysis**: Use `--cve-id` to test on specific CVEs
2. **Verify AI recommendations**: Always review AI suggestions before acting
3. **Use appropriate models**: GPT-4 for accuracy, GPT-3.5-turbo for cost savings
4. **Monitor API usage**: Set up billing alerts with your provider
5. **Combine with traditional analysis**: Use AI as enhancement, not replacement
6. **Review conflicts**: Pay attention to `review_recommended` flags

## Limitations

- Requires internet connection
- Subject to API rate limits
- May have latency (1-5 seconds per CVE)
- Accuracy depends on model and prompt quality
- No guarantee of correctness (always verify)

## Troubleshooting

### "AI Assistant not available"
- Check API key is set correctly
- Verify provider library is installed: `pip install openai` or `pip install anthropic`
- Check internet connectivity

### "AI API call failed"
- Verify API key is valid
- Check account has sufficient credits
- Review rate limits with provider
- Try with `--verbose` for detailed error messages

### Slow performance
- Use faster models (gpt-3.5-turbo, claude-haiku)
- Reduce batch sizes
- Check network latency

## Privacy and Security

- CVE data is sent to third-party AI providers
- Review your organization's data sharing policies
- Consider using on-premises LLM solutions for sensitive data
- API keys should be kept secure and never committed to version control

## Future Enhancements

- [ ] Support for local LLMs (Ollama, LM Studio)
- [ ] Caching of AI responses
- [ ] Custom prompts and fine-tuning
- [ ] Multi-model consensus
- [ ] Cost tracking and budgeting

## Support

For issues or questions about AI features:
- Check the main README for general troubleshooting
- Review AI provider documentation
- Open an issue on GitHub

---

*AI Assistant powered by OpenAI and Anthropic*
