#!/usr/bin/env python3
"""
Report Generation Handler Utility for Cyber-AutoAgent

This module provides report generation functionality that is called
directly by handlers (ReactBridgeHandler) at the
end of operations to guarantee report generation.

The actual report generation is done by a specialized Report Agent
that has access to the build_report_sections tool.

This is NOT a Strands tool - it's a handler utility function.
"""

import json
from typing import Any, Dict, List, Optional

from modules.agents.report_agent import ReportGenerator
from modules.config.system.logger import get_logger
from modules.tools.memory import get_memory_client

logger = get_logger("Handlers.ReportGenerator")

def generate_security_report(
    target: str,
    objective: str,
    operation_id: str,
    config_data: Optional[str] = None,
) -> str:
    """
    Generate a comprehensive security assessment report based on the operation results.

    This function is called by handlers to create a professional penetration testing
    report by analyzing the evidence collected during the security assessment.
    It uses a specialized Report Agent with tools to generate a well-structured
    report with findings, recommendations, and risk assessments.

    Args:
        target: The target system that was assessed
        objective: The security assessment objective
        operation_id: The operation identifier
        config_data: JSON string containing additional config (steps_executed, tools_used,
                    evidence, provider, model_id, module)

    Returns:
        The generated security assessment report as a string

    Example:
        generate_security_report(
            target="example.com",
            objective="Identify web application vulnerabilities",
            operation_id="OP_20240115_143022",
            config_data='{"steps_executed": 15, "tools_used": ["nmap", "nikto"], "provider": "bedrock"}'
        )
    """
    try:
        # Log the report generation request
        logger.info("Generating security report for operation: %s", operation_id)

        # Parse config data
        config_params = {}
        if config_data:
            try:
                config_params = json.loads(config_data)
            except json.JSONDecodeError:
                logger.error("Invalid JSON in config_data parameter")
                return "Report generation failed: Invalid configuration format"

        # Extract parameters with defaults
        steps_executed = config_params.get("steps_executed", 0)
        tools_used = config_params.get("tools_used", [])
        evidence = config_params.get("evidence")
        provider = config_params.get("provider", "bedrock")
        model_id = config_params.get("model_id")
        module = config_params.get("module")

        # If evidence not provided, retrieve from memory
        if evidence is None:
            evidence = _retrieve_evidence_from_memory(operation_id)

        # Validate evidence collection - skip report only if truly no memories
        if not evidence or len(evidence) == 0:
            logger.info(
                "No evidence/memories collected for operation %s - skipping report generation",
                operation_id,
            )
            return ""

        # Count different evidence types
        finding_count = len([e for e in evidence if e.get("category") == "finding"])
        observation_count = len([e for e in evidence if e.get("category") == "observation"])
        discovery_count = len([e for e in evidence if e.get("category") == "discovery"])
        signal_count = len([e for e in evidence if e.get("category") == "signal"])

        logger.info(
            "Retrieved %d pieces of evidence for report: %d findings, %d observations, %d discoveries, %d signals",
            len(evidence),
            finding_count,
            observation_count,
            discovery_count,
            signal_count,
        )

        # Generate report even with only observations (partial results)
        if finding_count == 0:
            logger.info("No findings, but generating report with observations/discoveries")

        # Get module report prompt if available for domain guidance
        module_report_prompt = _get_module_report_prompt(module)

        # Load the report template, preferring module-specific template when available
        from modules.prompts import load_prompt_template

        # If a module-specific report prompt exists (e.g., ctf/report_prompt.md), use it as the template
        if module_report_prompt and str(module_report_prompt).strip():
            report_template = module_report_prompt
            logger.info("Using module-specific report template for module: %s", module)
        else:
            report_template = load_prompt_template("report_template.md")
            logger.info("Using default security assessment report template")

        # Create report agent with the builder tool
        report_agent = ReportGenerator.create_report_agent(
            provider=provider,
            model_id=model_id,
            operation_id=operation_id,
            target=target,
        )

        # Create comprehensive prompt with template structure and module guidance
        # Using string concatenation/format to avoid f-string issues with template placeholders
        agent_prompt = """<operation_context>
Target: {target}
Objective: {objective}
Operation ID: {operation_id}
Module: {module}
Steps Executed: {steps_executed}
Tools Used Count: {tools_count}
</operation_context>

<module_guidance>
{module_guidance}
</module_guidance>

<report_template_instructions>
Use the following template structure for your report. Fill in each section with data from your build_report_sections tool:

{report_template}
</report_template_instructions>

<generation_instructions>
1. **First Step**: Call your build_report_sections tool with these parameters:
   - operation_id: "{operation_id}"
   - target: "{target}"
   - objective: "{objective}"
   - module: "{module}"
   - steps_executed: {steps_executed}
   - tools_used: {tools_used}

2. **Second Step**: Use the data returned by your tool to fill in the template above:
   - Most sections are pre-formatted and ready for direct insertion
   - For {{attack_path_analysis}}, {{mitre_attck_mapping}}, and {{technical_appendix}}, generate from raw_evidence.

   **Module Report Context**: Based on module and objective, briefly describe the assessment focus

   **Visual Summary**: Create a mermaid diagram visualizing the assessment findings.
   Example structure (customize based on actual findings):
   ```mermaid
   graph TD
       A[Target] --> B[Total Findings Count]
       B --> C1[Critical: X]
       B --> C2[High: Y]
       B --> C3[Medium: Z]
       
       C1 --> D1[Actual vulnerability names from raw_evidence]
       C2 --> D2[Actual vulnerability names from raw_evidence]
       
       D1 --> E[Impact/Exploitation paths]
   ```
   - Use the real target name and counts provided
   - Replace example text with actual vulnerability names from raw_evidence
   - Show actual affected systems from the location field
   - Connect related vulnerabilities that could be chained together

   **Attack Path Analysis**: Based on raw_evidence list, create:
   - Primary attack vectors showing how vulnerabilities chain together
   - Mermaid diagram mapping findings to attack flow.
     Example structure (build from actual evidence):
     ```mermaid
     graph LR
         A[External Attacker] --> B[Initial Access]
         B --> C[Vulnerability from raw_evidence (evidence id: <id>)]
         C --> D[Next step based on evidence]
         D --> E[Impact from evidence]
     ```
     * Replace generic terms with actual vulnerability names from raw_evidence
     * When a node originates from a specific finding, append "(evidence id: <id>)" using the `id` field from raw_evidence for traceability
     * Show the real attack progression based on your findings
     * Include specific endpoints/systems from the location field
     * Connect vulnerabilities based on their relationships in the evidence
   - Detection opportunities specific to the discovered attack patterns

   **MITRE ATT&CK Mapping**: Generate a mapping of tactics and techniques that are explicitly supported by the raw_evidence. Only include items that are clearly justified by the findings (no speculation). If uncertain, omit or mark as TBD. Group mappings by attack path nodes when possible.
   
   **Technical Appendix**: Based on raw_evidence and tools_used, create:
   - Proof of concept code snippets (sanitized) from evidence field
   - Configuration examples to remediate the findings
   - SIEM/IDS detection rules specific to the vulnerabilities found
   - Include actual payloads/commands from evidence where relevant
  
  - Use raw_evidence array which contains all parsed finding details
  - Generate content specific to the actual vulnerabilities found, not generic

3. **Final Step**: Output the complete report following the template structure exactly
  - Start IMMEDIATELY with "# SECURITY ASSESSMENT REPORT"
  - Do NOT include any preamble text like "Now I'll generate..." or "Let me create..."
  - Do NOT explain what you're doing - just output the report directly
  - Output ONLY the markdown report content - nothing else
  
  **CRITICAL REQUIREMENTS**:
  - Generate a comprehensive, detailed report within the model's token limits
  - NEVER truncate findings with text like "[Additional findings truncated for length]"
  - Include ALL critical findings from the build_report_sections tool
  - Include ALL high findings from the build_report_sections tool
  - If you have space, include medium and low findings as well
  - The report should be detailed and complete - do NOT abbreviate or truncate

  **CONSERVATIVE CLAIMS & NORMALIZATION**:
  - Use only claims grounded in raw_evidence; do NOT fabricate or speculate
  - Normalize severity to CRITICAL/HIGH/MEDIUM/LOW in all sections
  - Normalize confidence values to one decimal percent (e.g., 95.0%)
  - When financial impact is stated, label it as "Potential impact (estimated)" and add a brief assumptions note
  - If a remediation is unknown, write "TBD — requires protocol review"

Remember: You MUST use your build_report_sections tool first to get the evidence and analysis data.
</generation_instructions>"""
        # Safely format the agent prompt with runtime values
        # Escape braces in the report template so Python format doesn't consume them
        report_template_escaped = report_template.replace("{", "{{").replace("}", "}}")
        tools_json = json.dumps(tools_used) if tools_used else "[]"
        module_str = module or "general"
        module_guidance = (
            module_report_prompt
            if module_report_prompt
            else "Apply general security assessment best practices focusing on OWASP Top 10 and common vulnerability patterns."
        )
        agent_prompt = agent_prompt.format(
            target=target,
            objective=objective,
            operation_id=operation_id,
            module=module_str,
            steps_executed=steps_executed,
            tools_count=len(tools_used) if tools_used else 0,
            module_guidance=module_guidance,
            report_template=report_template_escaped,
            tools_used=tools_json,
        )

        # Generate the report using the agent with its tool
        logger.info("Invoking report generation agent with structured prompt...")
        result = report_agent(agent_prompt)

        # Extract the report content
        if result and hasattr(result, "message"):
            content = result.message.get("content", [])
            if content and isinstance(content, list):
                report_text = ""
                for block in content:
                    if isinstance(block, dict) and "text" in block:
                        report_text += block["text"]

                logger.info(
                    "Report generated successfully (%d characters)", len(report_text)
                )
                return report_text

        logger.error("Failed to generate report - no content in response")
        return "Error: Failed to generate security assessment report"

    except Exception as e:
        logger.error("Error generating security report: %s", e, exc_info=True)
        # Don't expose internal error details to user
        return "Report generation failed. Please check logs for details."


def _retrieve_evidence_from_memory(_operation_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve evidence from memory system for the operation.

    Args:
        operation_id: The operation ID to retrieve evidence for

    Returns:
        List of evidence dictionaries
    """
    evidence = []

    try:
        # Use pre-imported memory client with silent mode to prevent output during report generation
        memory_client = get_memory_client(silent=True)
        if not memory_client:
            error_msg = "Critical: Memory service unavailable - cannot generate comprehensive report with stored evidence"
            logger.error(error_msg)
            # Still proceed but with clear indication of missing data
            evidence.append(
                {
                    "category": "system_warning",
                    "content": "⚠️ WARNING: Memory service unavailable - report generated without stored evidence from previous assessment steps",
                    "severity": "HIGH",
                    "confidence": "SYSTEM",
                }
            )
            return evidence

        # Use native mem0 search with run_id for O(log n) indexed lookup
        # Note: With per-operation isolation, this queries current operation's store only
        # Cross-learning requires explicit querying of other operation stores
        try:
            logger.info("Retrieving evidence for operation %s", _operation_id)

            # Primary: Search with run_id for operation-scoped memories
            # Note: Use simple list format for FAISS compatibility (not {"in": [...]} syntax)
            op_scoped_memories = memory_client.search(
                query="findings evidence observations discoveries signals",
                user_id="cyber_agent",
                agent_id="cyber_agent",
                run_id=_operation_id,  # Native operation scoping (mem0 1.0.0 API)
                filters={
                    "category": ["finding", "signal", "observation", "discovery"]
                },
                limit=100
            )

            # Debug: Log what was found
            if op_scoped_memories:
                categories = {}
                for m in op_scoped_memories:
                    cat = m.get("metadata", {}).get("category", "MISSING")
                    categories[cat] = categories.get(cat, 0) + 1
                logger.debug("Operation-scoped search returned categories: %s", categories)

            # Use operation-scoped memories (no fallback - cross-learning requires shared mode)
            scoped = op_scoped_memories or []
            if scoped:
                logger.info(
                    "Found %d memories for operation %s",
                    len(scoped),
                    _operation_id,
                )
            else:
                logger.warning(
                    "No memories found for operation %s. "
                    "Note: Cross-operation learning requires MEMORY_ISOLATION=shared",
                    _operation_id,
                )
        except Exception as search_error:
            logger.error(
                "Error during native mem0 search: %s",
                search_error
            )
            scoped = []

        # Filter and format memories
        for mem in scoped:
            metadata = mem.get("metadata", {})
            memory_content = mem.get("memory", "")
            memory_id = mem.get("id", "")

            # Include items explicitly tagged with evidence-related categories
            # Accept multiple categories: finding, signal, observation, discovery
            if metadata.get("category") in ["finding", "signal", "observation", "discovery"]:
                evidence.append(
                    {
                        "category": metadata.get("category", "finding"),
                        "content": memory_content,
                        "id": memory_id,
                        "severity": metadata.get("severity", "unknown"),
                        "confidence": metadata.get("confidence", "unknown"),
                    }
                )
                continue

            # Heuristic: include structured evidence entries with security markers as findings
            # General security markers - applies to all assessment types
            if any(
                marker in str(memory_content)
                for marker in [
                    "[VULNERABILITY]",
                    "[FINDING]",
                    "[DISCOVERY]",
                    "[SIGNAL]",
                    "[EXPLOIT]",
                    "[EVIDENCE]",
                    "[SUCCESS]",
                ]
            ):
                evidence.append(
                    {
                        "category": "finding",
                        "content": memory_content,
                        "id": memory_id,
                        "severity": metadata.get("severity", "unknown"),
                        "confidence": metadata.get("confidence", "unknown"),
                    }
                )

        # Diagnostic logging for memory retrieval debugging
        operation_ids = {}
        categories = {}
        for m in scoped:
            meta = m.get("metadata", {}) or {}
            op_id = meta.get("operation_id", "NO_OP_ID")
            cat = meta.get("category", "NO_CATEGORY")
            operation_ids[op_id] = operation_ids.get(op_id, 0) + 1
            categories[cat] = categories.get(cat, 0) + 1

        non_findings_count = len(scoped) - len(evidence)
        logger.info(
            "Retrieved %d pieces of evidence from memory (filtered out %d non-findings: %s)",
            len(evidence),
            non_findings_count,
            ", ".join(f"{k}={v}" for k, v in categories.items()),
        )
        logger.debug("Memory operation_ids: %s", dict(operation_ids))

    except Exception as e:
        logger.warning("Error retrieving evidence from memory: %s", e)

    return evidence


def _get_module_report_prompt(module_name: Optional[str]) -> Optional[str]:
    """Get the module-specific report prompt if available.

    Args:
        module_name: Name of the module to load report prompt for

    Returns:
        Module report prompt string or None if not available
    """
    if not module_name:
        return None

    try:
        from modules.prompts import get_module_loader  # Dynamic import required

        module_loader = get_module_loader()
        module_report_prompt = module_loader.load_module_report_prompt(module_name)

        if module_report_prompt:
            logger.info(
                "Loaded report prompt for module '%s' (%d chars)",
                module_name,
                len(module_report_prompt),
            )
        else:
            logger.debug("No report prompt found for module '%s'", module_name)

        return module_report_prompt

    except Exception as e:
        logger.warning(
            "Error loading report prompt for module '%s': %s. Using default guidance.",
            module_name,
            e,
        )
        # Return default security assessment guidance as fallback
        return (
            "DOMAIN_LENS:\n"
            "overview: Security assessment focused on identifying vulnerabilities and risks\n"
            "analysis: Analyze findings for exploitability and business impact\n"
            "immediate: Address critical security vulnerabilities immediately\n"
            "short_term: Implement security controls and monitoring\n"
            "long_term: Establish comprehensive security program\n"
        )
