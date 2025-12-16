---
title: CodeQL Database Creation
description: Creating and managing CodeQL databases for analysis
---

# CodeQL Database Creation

CodeQL analyzes code by first creating a relational database that captures the structure and semantics of your codebase. This guide covers database creation, management, and optimization.

## Database Fundamentals

### What is a CodeQL Database?

A CodeQL database is a structured representation of your source code that includes:

- **Abstract Syntax Tree (AST)** - Complete parse tree of all code
- **Type Information** - Resolved types and type hierarchies
- **Control Flow Graph** - Execution paths through functions
- **Data Flow Graph** - How data moves through the program
- **Call Graph** - Function call relationships
- **Symbol Table** - All identifiers and their definitions

### Database Structure

```
codeql-database/
├── db-python/           # Language-specific data
│   ├── default/
│   │   └── cache/       # Extracted data
│   └── semmlecode.python.dbscheme
├── src/                 # Source archive
│   └── vulnerable-app/  # Copy of analyzed code
├── codeql-database.yml  # Database metadata
└── baseline-info.json   # Creation info
```

## Creating Databases

### Basic Creation

```bash
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app
```

### With Build Commands

For compiled languages or projects requiring setup:

```bash
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  --command="pip install -r requirements.txt"
```

### Multi-Language Databases

```bash
# Create databases for multiple languages
codeql database create vulnshop-db \
  --language=python \
  --language=javascript \
  --source-root=.
```

## Command Options

### Essential Options

| Option | Description | Example |
|--------|-------------|---------|
| `--language` | Programming language | `python`, `javascript`, `java` |
| `--source-root` | Root directory of source code | `./vulnerable-app` |
| `--command` | Build command to run | `"pip install -e ."` |
| `--overwrite` | Overwrite existing database | Flag only |

### Advanced Options

| Option | Description | Example |
|--------|-------------|---------|
| `--threads` | Number of extraction threads | `8` |
| `--ram` | Memory limit in MB | `8192` |
| `--search-path` | Additional QL packs location | `./custom-packs` |
| `--extractor-option` | Language-specific options | `python.python_version=3.10` |

### Python-Specific Options

```bash
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  --extractor-option="python.python_version=3.10" \
  --extractor-option="python.analysis.type_checking=basic"
```

## VulnShop Database Creation

### Complete Script

```bash
#!/bin/bash
# scripts/create_database.sh

set -e

DB_NAME="${1:-vulnshop-db}"
SOURCE_ROOT="${2:-../../vulnerable-app}"

echo "Creating CodeQL database: ${DB_NAME}"

# Remove existing database
rm -rf "${DB_NAME}"

# Create database with optimal settings
codeql database create "${DB_NAME}" \
  --language=python \
  --source-root="${SOURCE_ROOT}" \
  --threads=4 \
  --ram=4096 \
  --overwrite \
  2>&1 | tee database_creation.log

# Verify database
echo "Verifying database..."
codeql database info "${DB_NAME}"

echo "Database created successfully!"
echo "Database size: $(du -sh ${DB_NAME} | cut -f1)"
```

### Running the Script

```bash
cd analysis/codeql
chmod +x scripts/create_database.sh
./scripts/create_database.sh
```

## Database Management

### Viewing Database Info

```bash
codeql database info vulnshop-db
```

Output:
```
Database properties:
  source root: /path/to/vulnerable-app
  languages: python
  creation time: 2024-01-15 10:30:00
  SHA1 of codeql-database.yml: abc123...
```

### Upgrading Databases

When CodeQL CLI is updated, upgrade databases:

```bash
codeql database upgrade vulnshop-db
```

### Cleaning Databases

Remove cached query results:

```bash
codeql database cleanup vulnshop-db
```

### Bundling for Sharing

```bash
# Create distributable bundle
codeql database bundle vulnshop-db \
  --output vulnshop-db.zip

# Extract bundle
codeql database unbundle vulnshop-db.zip
```

## Source Archives

### Understanding Source Archives

CodeQL copies source code into the database for accurate location reporting:

```bash
# View archived sources
ls vulnshop-db/src/
```

### Customizing Source Inclusion

```bash
# Exclude certain files from archive
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  --no-source-archive  # Omit sources (smaller, but less useful)
```

### Source Root Configuration

```yaml
# codeql-config.yml
source-root: vulnerable-app
paths:
  - authentication/
  - catalog/
  - cart/
paths-ignore:
  - "**/tests/**"
  - "**/migrations/**"
```

## Performance Optimization

### Parallelization

```bash
# Use multiple threads for extraction
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  --threads=$(nproc)
```

### Memory Management

```bash
# Increase memory for large codebases
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  --ram=16384
```

### Incremental Updates

Currently, CodeQL doesn't support true incremental database updates. Best practice:

1. Store database creation script in repository
2. Recreate database on significant changes
3. Cache databases in CI/CD where possible

## CI/CD Integration

### GitHub Actions

```yaml
name: CodeQL Database Creation

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  create-database:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python
          config-file: .github/codeql/codeql-config.yml

      - name: Build (if needed)
        run: pip install -r requirements.txt

      - name: Perform Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:python"
```

### Local CI Script

```bash
#!/bin/bash
# ci/create_and_analyze.sh

# Create fresh database
codeql database create ci-db \
  --language=python \
  --source-root=. \
  --overwrite

# Run analysis
codeql database analyze ci-db \
  --format=sarif-latest \
  --output=results.sarif \
  analysis/codeql/suites/vulnshop-security.qls

# Check for critical findings
critical=$(jq '[.runs[].results[] | select(.level=="error")] | length' results.sarif)
if [ "$critical" -gt 0 ]; then
  echo "Found $critical critical issues!"
  exit 1
fi
```

## Troubleshooting

### "No source code found"

```bash
# Verify source root exists
ls -la vulnerable-app/

# Check Python files are present
find vulnerable-app -name "*.py" | head -10
```

### "Extraction failed"

```bash
# Run with verbose output
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  -v 2>&1 | tee extraction.log

# Check extraction logs
cat vulnshop-db/log/database-create*.log
```

### "Out of memory"

```bash
# Reduce threads and increase RAM
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app \
  --threads=2 \
  --ram=8192
```

### "Unknown language"

```bash
# List supported languages
codeql resolve languages

# Check extractor installation
codeql resolve extractor --language=python
```

## Database Queries

Once created, explore your database:

```bash
# Run quick query
codeql query run --database=vulnshop-db \
  --output=results.bqrs \
  'import python
   select count(File f)'

# Decode results
codeql bqrs decode results.bqrs
```

## Best Practices

### 1. Version Control Database Scripts

```bash
# Store creation script
git add analysis/codeql/scripts/create_database.sh
```

### 2. Document Database Requirements

```markdown
# Database Requirements
- CodeQL CLI 2.15.0+
- Python 3.10+
- 8GB RAM recommended
```

### 3. Validate Before Analysis

```bash
# Always verify database integrity
codeql database info vulnshop-db
codeql database check vulnshop-db
```

### 4. Keep Databases Fresh

```bash
# Recreate weekly or after significant changes
rm -rf vulnshop-db
./scripts/create_database.sh
```

## Next Steps

- [Writing Queries](queries.md) - Learn to write QL queries
- [Advanced Techniques](advanced.md) - Complex analysis patterns
- [CodeQL Overview](index.md) - Return to main guide
