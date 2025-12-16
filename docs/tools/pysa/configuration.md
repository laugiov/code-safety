---
title: Pysa Configuration
description: Complete guide to configuring Pysa for taint analysis
---

# Pysa Configuration

This guide covers all aspects of configuring Pysa for effective taint analysis on Python projects.

## Configuration Files Overview

Pysa requires several configuration files:

```
analysis/pysa/
├── .pyre_configuration      # Main Pyre/Pysa configuration
├── taint.config             # Taint rules and features
├── models/                  # Source, sink, and sanitizer definitions
│   ├── django_sources.pysa
│   ├── django_sinks.pysa
│   ├── django_sanitizers.pysa
│   └── ...
└── stubs/                   # Type stubs for untyped libraries
```

## .pyre_configuration

The main configuration file in JSON format:

```json
{
  "source_directories": [
    "../../vulnerable-app"
  ],
  "taint_models_path": [
    "models"
  ],
  "search_path": [
    "stubs",
    {"site-package": "django"}
  ],
  "exclude": [
    ".*/migrations/.*",
    ".*/tests/.*",
    ".*__pycache__.*"
  ],
  "strict": false,
  "analyze_external_sources": true
}
```

### Key Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `source_directories` | Directories to analyze | `["../../vulnerable-app"]` |
| `taint_models_path` | Location of `.pysa` model files | `["models"]` |
| `search_path` | Additional type information sources | `["stubs", {"site-package": "django"}]` |
| `exclude` | Patterns to exclude from analysis | `[".*/tests/.*"]` |
| `strict` | Enable strict type checking | `false` for most projects |

## taint.config

Defines the rules connecting sources to sinks:

```json
{
  "sources": [
    {
      "name": "UserControlled",
      "comment": "Data from HTTP requests"
    },
    {
      "name": "Cookies",
      "comment": "Data from cookies"
    },
    {
      "name": "DatabaseRead",
      "comment": "Data read from database"
    },
    {
      "name": "FileRead",
      "comment": "Data read from files"
    }
  ],
  "sinks": [
    {
      "name": "SQL",
      "comment": "SQL query execution"
    },
    {
      "name": "RemoteCodeExecution",
      "comment": "Command execution"
    },
    {
      "name": "XSS",
      "comment": "HTML response output"
    },
    {
      "name": "FileSystem",
      "comment": "File path operations"
    },
    {
      "name": "SSRF",
      "comment": "Server-side requests"
    },
    {
      "name": "Deserialization",
      "comment": "Object deserialization"
    },
    {
      "name": "Logging",
      "comment": "Log output"
    }
  ],
  "features": [
    {
      "name": "via-format-string",
      "comment": "Taint flows through format string"
    },
    {
      "name": "via-concatenation",
      "comment": "Taint flows through string concatenation"
    }
  ],
  "rules": [
    {
      "name": "SQL Injection",
      "code": 5001,
      "sources": ["UserControlled"],
      "sinks": ["SQL"],
      "message_format": "User-controlled data flows to SQL query"
    },
    {
      "name": "Command Injection",
      "code": 5003,
      "sources": ["UserControlled"],
      "sinks": ["RemoteCodeExecution"],
      "message_format": "User-controlled data flows to command execution"
    },
    {
      "name": "Path Traversal",
      "code": 5004,
      "sources": ["UserControlled"],
      "sinks": ["FileSystem"],
      "message_format": "User-controlled data flows to file path"
    },
    {
      "name": "SSRF",
      "code": 5005,
      "sources": ["UserControlled"],
      "sinks": ["SSRF"],
      "message_format": "User-controlled data flows to HTTP request"
    },
    {
      "name": "XSS",
      "code": 5006,
      "sources": ["UserControlled", "DatabaseRead"],
      "sinks": ["XSS"],
      "message_format": "Potentially tainted data flows to HTML output"
    },
    {
      "name": "Insecure Deserialization",
      "code": 5007,
      "sources": ["UserControlled"],
      "sinks": ["Deserialization"],
      "message_format": "User-controlled data flows to deserialization"
    },
    {
      "name": "Sensitive Data Logging",
      "code": 5008,
      "sources": ["Cookies", "UserControlled"],
      "sinks": ["Logging"],
      "message_format": "Sensitive data flows to log output"
    }
  ],
  "implicit_sources": {},
  "implicit_sinks": {}
}
```

## Multi-Source Rules

Some vulnerabilities involve multiple source types:

```json
{
  "name": "Stored XSS",
  "code": 5006,
  "sources": ["UserControlled", "DatabaseRead"],
  "sinks": ["XSS"],
  "message_format": "Data from {$sources} flows to HTML output"
}
```

This detects both:
- **Reflected XSS**: `UserControlled` → `XSS`
- **Stored XSS**: `UserControlled` → Database → `DatabaseRead` → `XSS`

## Features for Debugging

Features help track how taint propagates:

```json
{
  "features": [
    {"name": "via-format-string"},
    {"name": "via-concatenation"},
    {"name": "via-getattr"},
    {"name": "via-dictionary-access"}
  ]
}
```

When Pysa reports a finding, features show the propagation path:

```
Issue: SQL Injection
  Sources: UserControlled
  Sinks: SQL
  Features: via-format-string, via-concatenation
```

## Environment Variables

Configure Pysa behavior via environment:

```bash
# Increase analysis depth
export PYSA_ANALYSIS_DEPTH=5

# Enable verbose output
export PYRE_LOG_LEVEL=debug

# Control parallelism
export PYRE_WORKERS=4
```

## Project-Specific Configuration

### Django Projects

```json
{
  "source_directories": ["."],
  "search_path": [
    {"site-package": "django"},
    {"site-package": "rest_framework"}
  ],
  "taint_models_path": ["models"],
  "exclude": [
    ".*/migrations/.*",
    ".*/static/.*",
    ".*/templates/.*"
  ]
}
```

### Flask Projects

```json
{
  "source_directories": ["."],
  "search_path": [
    {"site-package": "flask"},
    {"site-package": "werkzeug"}
  ],
  "taint_models_path": ["models"]
}
```

### FastAPI Projects

```json
{
  "source_directories": ["."],
  "search_path": [
    {"site-package": "fastapi"},
    {"site-package": "starlette"},
    {"site-package": "pydantic"}
  ],
  "taint_models_path": ["models"]
}
```

## Optimization Settings

For large codebases:

```json
{
  "number_of_workers": 8,
  "parallel": true,
  "shared_memory": {
    "heap_size": 8589934592,
    "dependency_table_power": 27
  }
}
```

## Common Configuration Patterns

### Excluding Test Files

```json
{
  "exclude": [
    ".*/tests/.*",
    ".*/test_.*\\.py",
    ".*_test\\.py"
  ]
}
```

### Handling Virtual Environments

```json
{
  "search_path": [
    {"root": "/path/to/venv/lib/python3.10/site-packages"}
  ],
  "exclude": [
    ".*/venv/.*",
    ".*/\\.venv/.*"
  ]
}
```

### Monorepo Setup

```json
{
  "source_directories": [
    "services/api",
    "services/worker",
    "shared/common"
  ],
  "taint_models_path": [
    "security/pysa/models"
  ]
}
```

## Validation

Verify your configuration:

```bash
# Check configuration syntax
pyre check

# Run Pysa with verbose output
pyre analyze --dump-call-graph

# Validate models
pyre analyze --verify-models
```

## Next Steps

- [Writing Models](models.md) - Create custom source/sink definitions
- [Running Pysa](running.md) - Execute and interpret analysis
- [Advanced Techniques](advanced.md) - Complex patterns and optimization
