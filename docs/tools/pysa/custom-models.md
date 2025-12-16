---
title: Custom Pysa Models
description: Guide to writing custom .pysa model files
---

# Custom Pysa Models

This page redirects to the comprehensive [Writing Models](models.md) guide.

For quick reference:

## Source Definition

```python
def module.function() -> TaintSource[SourceKind]: ...
```

## Sink Definition

```python
def module.function(param: TaintSink[SinkKind]): ...
```

## Sanitizer Definition

```python
def module.sanitize(input: TaintInTaintOut[LocalReturn, NoTaint]): ...
```

See [Writing Models](models.md) for complete documentation.
