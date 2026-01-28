#!/usr/bin/env python3
"""
Tests for report_builder operation_id filtering logic.
- Current implementation FILTERS by operation_id for per-operation reports
- Memories with matching operation_id are included
- Memories with different operation_id are EXCLUDED
- Memories WITHOUT operation_id (untagged) are included for backward compatibility
"""
import json
import os
from unittest.mock import patch

import pytest

from modules.tools.memory import clear_memory_client
from modules.tools.report_builder import build_report_sections


@pytest.fixture(autouse=True)
def memory_client_clear():
    clear_memory_client()


@patch("modules.tools.memory.Mem0ServiceClient")
def test_report_builder_full_range_of_evidence(mock_client_cls, tmp_path):
    op_id = "OP_ALLOFIT"

    output_dir = tmp_path / "outputs"
    os.environ["CYBER_AGENT_OUTPUT_DIR"] = str(output_dir)
    try:
        operation_dir = output_dir / "example.com" / op_id
        operation_dir.mkdir(parents=True, exist_ok=True)

        plan = {
            "objective": "Perform recon on http://localhost:80",
            "current_phase": 4,
            "total_phases": 4,
            "phases": [
                {
                    "id": 1,
                    "title": "Initial Service Discovery",
                    "status": "done",
                    "criteria": "Identify running services and technologies"
                },
                {
                    "id": 2,
                    "title": "Endpoint Mapping",
                    "status": "done",
                    "criteria": "Map all accessible endpoints and parameters"
                },
                {
                    "id": 3,
                    "title": "Authentication Analysis",
                    "status": "done",
                    "criteria": "Analyze auth mechanisms and session handling"
                },
                {
                    "id": 4,
                    "title": "Vulnerability Identification",
                    "status": "done",
                    "criteria": "Identify potential vulnerabilities without exploitation"
                }
            ]
        }

        # Mock list_memories to return both tagged and untagged
        mock_client = mock_client_cls.return_value
        mock_client.list_memories.return_value = {
            "results": [
                {
                    "id": "2",
                    "memory": f"[PLAN]{json.dumps(plan)}",
                    "metadata": {"category": "plan", "operation_id": op_id, "active": True},
                },
                {
                    "id": "100",
                    "memory": "[VULNERABILITY] A [WHERE] /a [IMPACT] /a/impact [EVIDENCE] /a/evidence [STEPS] /a/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "CRITICAL", "confidence": "90",
                                 "validation_status": "verified"},
                },
                {
                    "id": "200",
                    "memory": "[VULNERABILITY] B [WHERE] /b [IMPACT] /b/impact [EVIDENCE] /b/evidence [STEPS] /b/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "HIGH", "confidence": "40",
                                 "validation_status": "hypothesis"},
                },
                {
                    "id": "201",
                    "memory": "[VULNERABILITY] C [WHERE] /c [IMPACT] /c/impact [EVIDENCE] /c/evidence [STEPS] /c/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "HIGH", "confidence": "90",
                                 "validation_status": "verified"},
                },
                {
                    "id": "300",
                    "memory": "[VULNERABILITY] D [WHERE] /d [IMPACT] /d/impact [EVIDENCE] /d/evidence [STEPS] /d/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "MEDIUM", "confidence": "90",
                                 "validation_status": "verified"},
                },
                {
                    "id": "301",
                    "memory": "[VULNERABILITY] E [WHERE] /e [IMPACT] /e/impact [EVIDENCE] /e/evidence [STEPS] /e/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "MEDIUM", "confidence": "80",
                                 "validation_status": "verified"},
                },
                {
                    "id": "302",
                    "memory": "[VULNERABILITY] F [WHERE] /f [IMPACT] /f/impact [EVIDENCE] /f/evidence [STEPS] /f/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "MEDIUM", "confidence": "30",
                                 "validation_status": "hypothesis"},
                },
                {
                    "id": "400",
                    "memory": "[VULNERABILITY] G [WHERE] /g [IMPACT] /g/impact [EVIDENCE] /g/evidence [STEPS] /g/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "LOW", "confidence": "90",
                                 "validation_status": "verified"},
                },
                {
                    "id": "401",
                    "memory": "[VULNERABILITY] H [WHERE] /h [IMPACT] /h/impact [EVIDENCE] /h/evidence [STEPS] /h/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "LOW", "confidence": "70",
                                 "validation_status": "verified"},
                },
                {
                    "id": "402",
                    "memory": "[VULNERABILITY] I [WHERE] /i [IMPACT] /i/impact [EVIDENCE] /i/evidence [STEPS] /i/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "LOW", "confidence": "50",
                                 "validation_status": "hypothesis"},
                },
                {
                    "id": "403",
                    "memory": "[VULNERABILITY] J [WHERE] /j [IMPACT] /j/impact [EVIDENCE] /j/evidence [STEPS] /j/steps",
                    "metadata": {"category": "finding", "operation_id": op_id, "severity": "LOW", "confidence": "20",
                                 "validation_status": "hypothesis"},
                },
                {
                    "id": "500",
                    "memory": "[OBSERVATION] K /k",
                    "metadata": {"category": "observation", "operation_id": op_id},
                },
                {
                    "id": "501",
                    "memory": "[OBSERVATION] L /l",
                    "metadata": {"category": "observation", "operation_id": op_id},
                },
                {
                    "id": "502",
                    "memory": "[OBSERVATION] M /m",
                    "metadata": {"category": "observation"},
                },
                {
                    "id": "503",
                    "memory": "[OBSERVATION] N /n",
                    "metadata": {"category": "observation"},
                },
                {
                    "id": "504",
                    "memory": "[OBSERVATION] O /o",
                    "metadata": {"category": "observation"},
                },
            ]
        }

        with open(operation_dir / "cyber_operations.log", "w", encoding="utf-8") as f:
            f.write(f'__CYBER_EVENT__{{"type": "metrics_update", "metrics": {{"tokens": 209251, "inputTokens": 208136, "outputTokens": 1115, "totalTokens": 209251, "cacheReadTokens": 0, "cacheWriteTokens": 0, "cost": 0.75, "duration": "20m 0s", "memoryOps": 2, "evidence": 1}}, "id": "{op_id}_171", "timestamp": "2026-01-26T21:29:49.060488"}}__CYBER_EVENT_END__\n')
            f.write(f'__CYBER_EVENT__{{"type": "metrics_update", "metrics": {{"tokens": 235860, "inputTokens": 234695, "outputTokens": 1165, "totalTokens": 235860, "cacheReadTokens": 0, "cacheWriteTokens": 0, "cost": 2.10, "duration": "21m 0s", "memoryOps": 2, "evidence": 1}}, "id": "{op_id}_185", "timestamp": "2026-01-26T21:30:49.111082"}}__CYBER_EVENT_END__\n')

        out = build_report_sections(
            operation_id=op_id,
            target="example.com",
            objective="test",
            module="web",
            steps_executed=197,
            tools_used=["shell", "shell", "python_repl", "shell", "python_repl", "stop"],
        )

        assert out.get("operation_id") == op_id
        assert out.get("target") == "example.com"
        assert out.get("objective") == "test"
        assert out.get("date")
        assert out.get("steps_executed") == 197
        assert out.get("severity_counts", {}) == {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        assert out.get("critical_count") == 1
        assert out.get("high_count") == 2
        assert out.get("medium_count") == 3
        assert out.get("low_count") == 4
        assert out.get("info_count") == 5
        assert out.get("module_report") == ""
        assert out.get("visual_summary") == ""
        assert "Comprehensive web application security assessment" in out.get("overview")
        assert json.loads(out.get("operation_plan", "{}")) == plan

        evidence_text = out.get("evidence_text")
        assert all([f" /{chr(c)}\n" in evidence_text for c in range(ord('a'), ord('p'))])
        assert "#### 11. INFO Observation"

        findings_table = out.get("findings_table")
        assert "CRITICAL | 1 |" in findings_table
        assert "HIGH | 2 |" in findings_table
        assert "MEDIUM | 3 |" in findings_table
        assert "LOW | 4 |" in findings_table
        assert "INFO |" not in findings_table

        critical_findings = out.get("critical_findings")
        assert critical_findings.count("#### ") == 1
        assert "#### 1. A - /a" in critical_findings
        assert "B - /b" not in critical_findings
        assert "K - /k" not in critical_findings

        high_findings = out.get("high_findings")
        assert high_findings.count("#### ") == 2
        assert "B - /b" in high_findings
        assert "C - /c" in high_findings
        assert "A - /a" not in high_findings
        assert "K - /k" not in high_findings

        summary_table = out.get("summary_table")
        assert summary_table.count("| MEDIUM |") == 3
        assert summary_table.count("| LOW |") == 4
        assert summary_table.count("| INFO |") == 5
        assert "|  |  |  |" not in summary_table

        assert "OWASP Top 10 vulnerabilities" in out.get("analysis")
        assert "Address critical authentication bypasses" in out.get("immediate_recommendations")
        assert "Deploy comprehensive security headers" in out.get("short_term_recommendations")
        assert "Adopt secure Software Development Life Cycle" in out.get("long_term_recommendations")

        raw_evidence = out.get("raw_evidence", [])
        assert len(raw_evidence) == 10
        assert all(["id" in e for e in raw_evidence])
        assert all(["severity" in e for e in raw_evidence])
        assert len(list(filter(lambda e: e["severity"] == "CRITICAL", raw_evidence))) == 1
        assert len(list(filter(lambda e: e["severity"] == "HIGH", raw_evidence))) == 2
        assert len(list(filter(lambda e: e["severity"] == "MEDIUM", raw_evidence))) == 3
        assert len(list(filter(lambda e: e["severity"] == "LOW", raw_evidence))) == 4
        assert len(list(filter(lambda e: e["severity"] == "INFO", raw_evidence))) == 0

        assert out.get("tools_summary") == "- shell: 3 uses\n- python_repl: 2 uses\n- stop: 1 use"
        assert "OWASP Top 10 2021" in out.get("analysis_framework")
        assert out.get("module") == "web"
        assert out.get("evidence_count") == 15
        assert out.get("canonical_findings", {}).keys() == {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}

        assert out.get("input_tokens") == 234695
        assert out.get("output_tokens") == 1165
        assert out.get("total_tokens") == 235860
        assert out.get("estimated_cost") == '2.1000'
        assert out.get("total_duration") == "21m 0s"

    finally:
        os.environ.pop("CYBER_AGENT_OUTPUT_DIR")

@patch("modules.tools.memory.Mem0ServiceClient")
def test_report_builder_filters_by_operation_id(mock_client_cls):
    """Report builder should filter evidence by operation_id for per-operation reports."""
    op_id = "OP_123"
    # Mock list_memories to return both tagged and untagged
    mock_client = mock_client_cls.return_value
    mock_client.list_memories.return_value = {
        "results": [
            {
                "id": "1",
                "memory": "[VULNERABILITY] A [WHERE] /a",
                "metadata": {"category": "finding", "operation_id": op_id},
            },
            {
                "id": "2",
                "memory": "[VULNERABILITY] B [WHERE] /b",
                "metadata": {"category": "finding", "operation_id": "OP_OTHER"},
            },
            {
                "id": "3",
                "memory": "[VULNERABILITY] C [WHERE] /c",
                "metadata": {"category": "finding"},
            },
        ]
    }

    out = build_report_sections(
        operation_id=op_id, target="example.com", objective="test", module="custom_module"
    )
    # Evidence from current operation should be included
    assert any(
        "/a" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Expected matching evidence from current operation"
    # Evidence from OTHER operations should be EXCLUDED (filtered out)
    assert not any(
        "/b" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Should EXCLUDE evidence from other operations"
    # Untagged evidence (no operation_id) should be included for backward compatibility
    assert any(
        "/c" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Should include untagged evidence for backward compatibility"

    assert out.get("severity_counts", {}) == {"critical": 0, "high": 0, "medium": 2, "low": 0, "info": 0}
    assert out.get("module") == "custom_module"


@patch("modules.tools.memory.Mem0ServiceClient")
@patch.dict(os.environ, {"MEMORY_ISOLATION": "shared"})
def test_report_builder_cross_operation(mock_client_cls):
    """Report builder should filter evidence by operation_id for per-operation reports."""
    op_id = "OP_123"
    # Mock list_memories to return both tagged and untagged
    mock_client = mock_client_cls.return_value
    mock_client.list_memories.return_value = {
        "results": [
            {
                "id": "1",
                "memory": "[VULNERABILITY] A [WHERE] /a",
                "metadata": {"category": "finding", "operation_id": op_id},
            },
            {
                "id": "2",
                "memory": "[VULNERABILITY] B [WHERE] /b",
                "metadata": {"category": "finding", "operation_id": "OP_OTHER"},
            },
            {
                "id": "3",
                "memory": "[VULNERABILITY] C [WHERE] /c",
                "metadata": {"category": "finding"},
            },
        ]
    }

    out = build_report_sections(
        operation_id=op_id, target="example.com", objective="test", module="custom_module"
    )
    # Evidence from current operation should be included
    assert any(
        "/a" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Expected matching evidence from current operation"
    # Evidence from OTHER operations should be EXCLUDED (filtered out)
    assert any(
        "/b" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Should INCLUDE evidence from other operations"
    # Untagged evidence (no operation_id) should be included for backward compatibility
    assert any(
        "/c" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Should include untagged evidence for backward compatibility"

    assert out.get("severity_counts", {}) == {"critical": 0, "high": 0, "medium": 3, "low": 0, "info": 0}


@patch("modules.tools.memory.Mem0ServiceClient")
def test_report_builder_includes_untagged_evidence(mock_client_cls):
    op_id = "OP_456"
    mock_client = mock_client_cls.return_value
    mock_client.list_memories.return_value = {
        "results": [
            {
                "id": "10",
                "memory": "[VULNERABILITY] Legacy [WHERE] /legacy",
                "metadata": {"category": "finding"},
            },
        ]
    }

    out = build_report_sections(
        operation_id=op_id, target="example.com", objective="test"
    )
    # Current implementation includes all evidence (no filtering by operation_id)
    assert out.get("raw_evidence"), "Untagged evidence should be included in the report"
    assert any(
        "/legacy" in e.get("content", "") for e in out.get("raw_evidence", []) or []
    ), "Should include untagged evidence"

    assert out.get("severity_counts", {}) == {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}


@patch("modules.tools.memory.Mem0ServiceClient")
def test_report_builder_only_has_info_evidence(mock_client_cls):
    """Report builder should include info evidence."""
    op_id = "OP_789"
    mock_client = mock_client_cls.return_value
    mock_client.list_memories.return_value = {
        "results": [
            {
                "id": "1",
                "memory": "[OBSERVATION] A [WHERE] /a",
                "metadata": {"category": "observation", "operation_id": op_id},
            },
            {
                "id": "2",
                "memory": "[OBSERVATION] B [WHERE] /b",
                "metadata": {"category": "discovery", "operation_id": op_id},
            },
            {
                "id": "3",
                "memory": "[OBSERVATION] C [WHERE] /c",
                "metadata": {"category": "signal", "operation_id": op_id},
            },
        ]
    }

    out = build_report_sections(
        operation_id=op_id, target="example.com", objective="test"
    )
    assert out.get("raw_evidence") == [], "Raw evidence should only include findings"
    evidence_text = out.get("evidence_text", "")
    assert "/a" in evidence_text, "Expected matching observation from current operation"
    assert "/b" in evidence_text, "Expected matching discovery from current operation"
    assert "/c" in evidence_text, "Expected matching signal from current operation"

    assert out.get("severity_counts", {}) == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 3}


@patch("modules.tools.memory.Mem0ServiceClient")
def test_report_builder_handles_memory_errors(mock_client_cls):
    mock_client = mock_client_cls.return_value
    mock_client.list_memories.side_effect = RuntimeError("boom")

    out = build_report_sections(
        operation_id="OP_ERR", target="example.com", objective="test"
    )
    assert isinstance(out, dict)
    assert out.get("raw_evidence") == [], (
        "Failures loading memories should yield empty evidence rather than crash"
    )

    assert out.get("severity_counts", {}) == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
