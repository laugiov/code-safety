## Description

Brief description of the changes in this PR.

Fixes #(issue number)

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] New vulnerability (adding vulnerability to VulnShop)
- [ ] New detection rule (Pysa model, CodeQL query, or Semgrep rule)
- [ ] Documentation update
- [ ] CI/CD improvement
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Other: ___________

## Changes Made

### Summary

- Change 1
- Change 2
- Change 3

### Details

Detailed explanation of changes if needed.

## For New Vulnerabilities

If adding a new vulnerability to VulnShop:

- [ ] Vulnerability is clearly documented in code comments
- [ ] Taint flow is documented (source → sink)
- [ ] CWE and OWASP references included
- [ ] Exploitation PoC is provided and tested
- [ ] Ground truth updated (`benchmarks/ground-truth/vulnerabilities.json`)
- [ ] Documentation added (`docs/en/vulnerabilities/`)

## For New Detection Rules

If adding detection rules:

- [ ] **Pysa**: Model added to `analysis/pysa/models/`
- [ ] **CodeQL**: Query added to `analysis/codeql/queries/`
- [ ] **Semgrep**: Rule added to `analysis/semgrep/rules/`
- [ ] Rule is tested against VulnShop
- [ ] False positive rate is acceptable
- [ ] Documentation updated

## Testing

Describe the tests you ran:

- [ ] Ran `make test`
- [ ] Ran `make lint`
- [ ] Tested manually: [describe]
- [ ] Ran analysis tools: [which ones]
- [ ] Verified Docker build: `docker-compose build`

### Test Results

```
Paste relevant test output here
```

## Documentation

- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated
- [ ] README updated (if applicable)

## Checklist

- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] New and existing tests pass locally
- [ ] Any dependent changes have been merged and published

## Screenshots / Output

If applicable, add screenshots or command output to show the changes.

## Additional Notes

Any additional information reviewers should know.
