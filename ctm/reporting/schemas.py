"""JSON schemas used to validate CTM's machine-readable report formats."""

CTM_REPORT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["report", "findings", "remediation_plan"],
    "properties": {
        "report": {
            "type": "object",
            "required": ["product", "report_type", "finding_count", "summary"],
            "properties": {
                "product": {"const": "Contextual Threat Modeler"},
                "report_type": {"const": "security_decision"},
                "finding_count": {"type": "integer", "minimum": 0},
                "summary": {
                    "type": "object",
                    "required": [
                        "total_findings",
                        "risk_levels",
                        "decisions",
                        "average_score",
                        "highest_score",
                        "mitre_techniques",
                        "stride_threats",
                    ],
                    "properties": {
                        "total_findings": {"type": "integer", "minimum": 0},
                        "risk_levels": {"type": "object"},
                        "decisions": {"type": "object"},
                        "average_score": {"type": "number", "minimum": 0, "maximum": 100},
                        "highest_score": {"type": "number", "minimum": 0, "maximum": 100},
                        "mitre_techniques": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "stride_threats": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "additionalProperties": True,
                },
            },
            "additionalProperties": True,
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "id",
                    "asset_id",
                    "method",
                    "path",
                    "endpoint_type",
                    "score",
                    "confidence",
                    "likelihood",
                    "impact",
                    "decision",
                    "rationale",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "method": {"type": "string"},
                    "path": {"type": "string"},
                    "endpoint_type": {"type": "string"},
                    "score": {"type": "number", "minimum": 0, "maximum": 100},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "likelihood": {"type": "number", "minimum": 0, "maximum": 10},
                    "impact": {"type": "number", "minimum": 0, "maximum": 10},
                    "decision": {
                        "enum": [
                            "TEST_IMMEDIATELY",
                            "PRIORITIZE_VALIDATION",
                            "INVESTIGATE",
                            "MONITOR",
                        ]
                    },
                    "rationale": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "additionalProperties": True,
            },
        },
        "remediation_plan": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "finding_id",
                    "priority",
                    "score",
                    "decision",
                    "action",
                    "rationale",
                ],
                "properties": {
                    "finding_id": {"type": "string"},
                    "priority": {"enum": ["P1", "P2", "P3", "P4"]},
                    "score": {"type": "number", "minimum": 0, "maximum": 100},
                    "decision": {"type": "string"},
                    "action": {"type": "string", "minLength": 1},
                    "rationale": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "trend": {"type": "object"},
    },
    "additionalProperties": False,
}

SARIF_REPORT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["$schema", "version", "runs"],
    "properties": {
        "$schema": {
            "const": "https://json.schemastore.org/sarif-2.1.0.json"
        },
        "version": {"const": "2.1.0"},
        "runs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "rules"],
                                "additionalProperties": True,
                                "properties": {
                                    "name": {"const": "Contextual Threat Modeler"},
                                    "rules": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "required": [
                                                "id",
                                                "name",
                                                "shortDescription",
                                                "defaultConfiguration",
                                            ],
                                            "properties": {
                                                "id": {"type": "string"},
                                                "name": {"type": "string"},
                                                "shortDescription": {
                                                    "type": "object",
                                                    "required": ["text"],
                                                    "properties": {"text": {"type": "string"}},
                                                },
                                                "defaultConfiguration": {
                                                    "type": "object",
                                                    "required": ["level"],
                                                    "properties": {
                                                        "level": {
                                                            "enum": [
                                                                "error",
                                                                "warning",
                                                                "note",
                                                                "none",
                                                            ]
                                                        }
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "ruleId",
                                "level",
                                "message",
                                "locations",
                                "properties",
                            ],
                            "properties": {
                                "ruleId": {"type": "string"},
                                "level": {"enum": ["error", "warning", "note", "none"]},
                                "message": {
                                    "type": "object",
                                    "required": ["text"],
                                    "properties": {"text": {"type": "string"}},
                                },
                                "locations": {
                                    "type": "array",
                                    "minItems": 1,
                                    "items": {
                                        "type": "object",
                                        "required": ["physicalLocation", "logicalLocations"],
                                        "properties": {
                                            "physicalLocation": {
                                                "type": "object",
                                                "required": ["artifactLocation"],
                                                "properties": {
                                                    "artifactLocation": {
                                                        "type": "object",
                                                        "required": ["uri"],
                                                        "properties": {"uri": {"type": "string"}},
                                                    }
                                                },
                                            },
                                            "logicalLocations": {"type": "array"},
                                        },
                                    },
                                },
                                "properties": {
                                    "type": "object",
                                    "required": [
                                        "findingId",
                                        "assetId",
                                        "riskScore",
                                        "confidence",
                                        "decision",
                                        "priority",
                                        "remediation",
                                        "rationale",
                                        "threats",
                                        "attackTechniques",
                                    ],
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    "additionalProperties": False,
}
