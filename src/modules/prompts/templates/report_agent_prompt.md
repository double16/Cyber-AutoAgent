<operation_context>
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
- Normalize severity to CRITICAL/HIGH/MEDIUM/LOW/INFO in all sections
- Normalize confidence values to one decimal percent (e.g., 95.0%)
- When financial impact is stated, label it as "Potential impact (estimated)" and add a brief assumptions note
- If a remediation is unknown, write "TBD — requires protocol review"

Remember: You MUST use your build_report_sections tool first to get the evidence and analysis data.
</generation_instructions>
