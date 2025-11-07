#!/usr/bin/env python3
"""
AI Assistant for VEX Kernel Checker.

This module provides AI-powered analysis capabilities for vulnerability assessment,
including CVE relevance detection, patch analysis, and security recommendations.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import VexKernelCheckerBase
from .common import Justification, Response, VulnerabilityState, timed_method
from .logging_utils import get_logger


class AIAssistant(VexKernelCheckerBase):
    """AI-powered assistant for vulnerability analysis."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4",
        provider: str = "openai",
        max_retries: int = 3,
        **kwargs
    ):
        """Initialize the AI Assistant.

        Args:
            api_key: API key for the AI provider (or set OPENAI_API_KEY, ANTHROPIC_API_KEY env var)
            model: Model to use (e.g., "gpt-4", "gpt-3.5-turbo", "claude-3-opus")
            provider: AI provider ("openai" or "anthropic")
            max_retries: Maximum number of API retry attempts
            **kwargs: Additional keyword arguments passed to base class
        """
        super().__init__(**kwargs)
        self.logger = get_logger(__name__)
        
        self.provider = provider.lower()
        self.model = model
        self.max_retries = max_retries
        self.api_key = api_key or self._get_api_key_from_env()
        self.client = None
        self.enabled = False
        
        if self.api_key:
            self._initialize_client()
        else:
            self.logger.info("AI Assistant disabled: No API key provided")

    def _get_api_key_from_env(self) -> Optional[str]:
        """Get API key from environment variables."""
        if self.provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif self.provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY")
        return None

    def _initialize_client(self):
        """Initialize the AI client based on provider."""
        try:
            if self.provider == "openai":
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
                self.enabled = True
                self.logger.info(f"AI Assistant initialized with OpenAI ({self.model})")
            elif self.provider == "anthropic":
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.enabled = True
                self.logger.info(f"AI Assistant initialized with Anthropic ({self.model})")
            else:
                self.logger.warning(f"Unsupported AI provider: {self.provider}")
        except ImportError as e:
            self.logger.warning(f"AI provider library not installed: {e}")
            self.logger.info("Install with: pip install openai anthropic")
        except Exception as e:
            self.logger.error(f"Failed to initialize AI client: {e}")

    @timed_method
    def analyze_cve_relevance(
        self,
        cve_id: str,
        description: str,
        kernel_config: Optional[Dict[str, bool]] = None,
        architecture: Optional[str] = None
    ) -> Tuple[bool, str, float]:
        """Use AI to analyze if a CVE is relevant to the kernel configuration.

        Args:
            cve_id: CVE identifier
            description: CVE description text
            kernel_config: Kernel configuration options
            architecture: Target architecture

        Returns:
            Tuple of (is_relevant, reasoning, confidence)
        """
        if not self.enabled:
            return False, "AI Assistant not available", 0.0

        # Build context
        context = f"CVE ID: {cve_id}\n\nDescription: {description}\n\n"
        
        if architecture:
            context += f"Target Architecture: {architecture}\n"
        
        if kernel_config:
            # Include relevant config options
            config_summary = []
            for key, value in list(kernel_config.items())[:20]:  # Limit to avoid token overflow
                config_summary.append(f"{key}={'enabled' if value else 'disabled'}")
            if config_summary:
                context += f"\nKernel Configuration (sample):\n" + "\n".join(config_summary)

        prompt = f"""Analyze this Linux kernel CVE and determine if it's relevant to the given configuration.

{context}

Consider:
1. Does the CVE affect Linux kernel components?
2. Are the affected components likely present in this configuration?
3. Does the architecture match any architecture-specific vulnerabilities?
4. Is this a driver, subsystem, or core kernel issue?

Respond in JSON format:
{{
    "is_relevant": true/false,
    "reasoning": "brief explanation of why it is or isn't relevant",
    "confidence": 0.0-1.0,
    "affected_components": ["list", "of", "components"],
    "recommended_action": "what should be done"
}}"""

        try:
            response = self._call_ai_api(prompt)
            result = json.loads(response)
            
            is_relevant = result.get("is_relevant", False)
            reasoning = result.get("reasoning", "No reasoning provided")
            confidence = float(result.get("confidence", 0.5))
            
            self.logger.debug(f"AI analysis for {cve_id}: relevant={is_relevant}, confidence={confidence}")
            
            return is_relevant, reasoning, confidence
            
        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse AI response for {cve_id}")
            return False, "AI response parsing failed", 0.0
        except Exception as e:
            self.logger.error(f"AI analysis failed for {cve_id}: {e}")
            return False, f"AI analysis error: {str(e)}", 0.0

    @timed_method
    def suggest_mitigation(
        self,
        cve_id: str,
        description: str,
        severity: str,
        patch_available: bool = False,
        config_options: Optional[List[str]] = None
    ) -> str:
        """Generate AI-powered mitigation recommendations.

        Args:
            cve_id: CVE identifier
            description: CVE description
            severity: Severity level
            patch_available: Whether a patch is available
            config_options: Relevant kernel config options

        Returns:
            Mitigation recommendation text
        """
        if not self.enabled:
            return "AI Assistant not available for recommendations"

        prompt = f"""Provide practical mitigation recommendations for this Linux kernel vulnerability.

CVE: {cve_id}
Severity: {severity}
Description: {description}
Patch Available: {'Yes' if patch_available else 'No'}
"""

        if config_options:
            prompt += f"\nRelevant Config Options: {', '.join(config_options)}\n"

        prompt += """
Provide specific, actionable recommendations including:
1. Immediate actions (if exploitable)
2. Configuration changes (if applicable)
3. Patch application steps (if available)
4. Workarounds (if patch not available)
5. Monitoring recommendations

Keep the response concise and practical (max 200 words)."""

        try:
            recommendation = self._call_ai_api(prompt)
            return recommendation.strip()
        except Exception as e:
            self.logger.error(f"Failed to generate mitigation for {cve_id}: {e}")
            return "Could not generate AI recommendations"

    @timed_method
    def enhance_vulnerability_analysis(
        self,
        cve_id: str,
        description: str,
        current_analysis: Optional[Dict[str, Any]] = None,
        kernel_config: Optional[Dict[str, bool]] = None
    ) -> Dict[str, Any]:
        """Enhance existing vulnerability analysis with AI insights.

        Args:
            cve_id: CVE identifier
            description: CVE description
            current_analysis: Current analysis results
            kernel_config: Kernel configuration

        Returns:
            Enhanced analysis dictionary with AI insights
        """
        if not self.enabled:
            return current_analysis or {}

        enhanced = current_analysis.copy() if current_analysis else {}
        
        # Get AI relevance analysis
        is_relevant, reasoning, confidence = self.analyze_cve_relevance(
            cve_id, description, kernel_config
        )
        
        # Add AI insights to analysis
        enhanced['ai_analysis'] = {
            'is_relevant': is_relevant,
            'reasoning': reasoning,
            'confidence': confidence,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        
        # If high confidence and conflicts with existing analysis, flag for review
        if confidence > 0.8 and current_analysis:
            current_state = current_analysis.get('state')
            ai_suggests_exploitable = is_relevant and confidence > 0.8
            current_says_not_affected = current_state == VulnerabilityState.NOT_AFFECTED.value
            
            if ai_suggests_exploitable and current_says_not_affected:
                enhanced['ai_analysis']['review_recommended'] = True
                enhanced['ai_analysis']['conflict'] = (
                    "AI analysis suggests vulnerability may be relevant, "
                    "but current analysis marked as not affected"
                )
        
        return enhanced

    def _call_ai_api(self, prompt: str) -> str:
        """Call the AI API with retry logic.

        Args:
            prompt: The prompt to send to the AI

        Returns:
            AI response text
        """
        for attempt in range(self.max_retries):
            try:
                if self.provider == "openai":
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": "You are a Linux kernel security expert helping analyze CVE vulnerabilities."
                            },
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.3,
                        max_tokens=1000
                    )
                    return response.choices[0].message.content
                    
                elif self.provider == "anthropic":
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=1000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return response.content[0].text
                    
            except Exception as e:
                self.logger.warning(f"AI API call attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise

        raise Exception("AI API call failed after all retries")

    def batch_analyze_cves(
        self,
        cve_list: List[Dict[str, Any]],
        kernel_config: Optional[Dict[str, bool]] = None,
        max_concurrent: int = 5
    ) -> List[Dict[str, Any]]:
        """Analyze multiple CVEs with AI assistance.

        Args:
            cve_list: List of CVE dictionaries with 'id' and 'description'
            kernel_config: Kernel configuration
            max_concurrent: Maximum concurrent API calls

        Returns:
            List of enhanced CVE analyses
        """
        if not self.enabled:
            return cve_list

        results = []
        self.logger.info(f"Starting AI batch analysis for {len(cve_list)} CVEs")
        
        for i, cve_data in enumerate(cve_list):
            if i > 0 and i % 10 == 0:
                self.logger.info(f"AI analyzed {i}/{len(cve_list)} CVEs")
            
            cve_id = cve_data.get('id', 'unknown')
            description = cve_data.get('description', '')
            
            enhanced = self.enhance_vulnerability_analysis(
                cve_id, description, cve_data, kernel_config
            )
            results.append(enhanced)
            
            # Rate limiting
            time.sleep(0.5)
        
        self.logger.info(f"AI batch analysis completed: {len(results)} CVEs processed")
        return results
