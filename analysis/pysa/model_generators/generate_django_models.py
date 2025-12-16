#!/usr/bin/env python3
"""
Django View Model Generator for Pysa

This script automatically generates Pysa taint models for Django view functions.
It scans the VulnShop application and creates models that mark request parameters
as taint sources.

Usage:
    python generate_django_models.py

Output:
    models/vulnshop_auto.pysa - Auto-generated view models
"""

import ast
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ViewFunction:
    """Represents a discovered Django view function."""
    name: str
    module_path: str
    file_path: str
    line_number: int
    args: List[str]
    decorators: List[str]
    docstring: Optional[str]
    has_request_param: bool


def find_view_files(source_dir: str) -> List[Path]:
    """
    Find all views.py files in a Django project.

    Args:
        source_dir: Root directory to search

    Returns:
        List of Path objects pointing to views.py files
    """
    source_path = Path(source_dir)
    view_files = []

    for views_file in source_path.rglob("views.py"):
        # Skip migrations, tests, and cache directories
        if any(part in views_file.parts for part in ['migrations', 'tests', '__pycache__', 'venv']):
            continue
        view_files.append(views_file)

    return sorted(view_files)


def extract_module_path(file_path: Path, base_dir: Path) -> str:
    """
    Convert file path to Python module path.

    Args:
        file_path: Path to the Python file
        base_dir: Base directory for the project

    Returns:
        Module path string (e.g., 'authentication.views')
    """
    relative_path = file_path.relative_to(base_dir)
    module_parts = list(relative_path.parts)

    # Remove .py extension from last part
    if module_parts[-1].endswith('.py'):
        module_parts[-1] = module_parts[-1][:-3]

    return '.'.join(module_parts)


def parse_view_file(file_path: Path, module_path: str) -> List[ViewFunction]:
    """
    Parse a views.py file and extract view function information.

    Args:
        file_path: Path to the views.py file
        module_path: Python module path

    Returns:
        List of ViewFunction objects
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Warning: Syntax error in {file_path}: {e}", file=sys.stderr)
        return []

    views = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            # Extract function arguments
            args = [arg.arg for arg in node.args.args]

            # Check if first argument is 'request' (Django view pattern)
            has_request = len(args) > 0 and args[0] == 'request'

            # Skip if not a view function (no request parameter)
            if not has_request:
                continue

            # Extract decorators
            decorators = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name):
                    decorators.append(decorator.id)
                elif isinstance(decorator, ast.Call):
                    if isinstance(decorator.func, ast.Name):
                        decorators.append(decorator.func.id)
                    elif isinstance(decorator.func, ast.Attribute):
                        decorators.append(decorator.func.attr)

            # Extract docstring
            docstring = ast.get_docstring(node)

            views.append(ViewFunction(
                name=node.name,
                module_path=module_path,
                file_path=str(file_path),
                line_number=node.lineno,
                args=args,
                decorators=decorators,
                docstring=docstring,
                has_request_param=has_request
            ))

    return views


def generate_pysa_model(view: ViewFunction) -> str:
    """
    Generate Pysa model declaration for a view function.

    Args:
        view: ViewFunction object

    Returns:
        Pysa model string
    """
    lines = []

    # Add comment with file location and vulnerability info
    lines.append(f"# {view.file_path}:{view.line_number}")

    # Extract vulnerability info from docstring if present
    if view.docstring:
        for line in view.docstring.split('\n'):
            if 'VULNERABILITY' in line.upper() or 'CWE-' in line:
                lines.append(f"# {line.strip()}")
                break

    # Build function signature
    args_str = []
    for arg in view.args:
        if arg == 'request':
            args_str.append("request: TaintSource[UserControlled]")
        elif arg == 'self':
            args_str.append("self")
        else:
            args_str.append(arg)

    func_def = f"def {view.module_path}.{view.name}({', '.join(args_str)}): ..."
    lines.append(func_def)

    return '\n'.join(lines)


def generate_models(source_dir: str, output_file: str) -> Tuple[int, List[ViewFunction]]:
    """
    Generate Pysa models for all view functions in a Django project.

    Args:
        source_dir: Root directory of the Django project
        output_file: Path to output .pysa file

    Returns:
        Tuple of (count of views, list of views)
    """
    source_path = Path(source_dir).resolve()

    # Find all view files
    view_files = find_view_files(source_dir)

    if not view_files:
        print(f"No views.py files found in {source_dir}", file=sys.stderr)
        return 0, []

    # Parse all view files
    all_views: List[ViewFunction] = []

    for view_file in view_files:
        module_path = extract_module_path(view_file, source_path)
        views = parse_view_file(view_file, module_path)
        all_views.extend(views)

    # Generate output
    output_lines = [
        "# Auto-generated Pysa models for VulnShop views",
        "# Generated by generate_django_models.py",
        "#",
        "# DO NOT EDIT MANUALLY - regenerate using:",
        "#   python model_generators/generate_django_models.py",
        "#",
        f"# Total views discovered: {len(all_views)}",
        "#",
        "# These models mark Django view request parameters as taint sources,",
        "# enabling Pysa to track data flow from HTTP requests to security sinks.",
        "",
        "# ==============================================================================",
        "# View Function Models",
        "# ==============================================================================",
        "",
    ]

    # Group views by module
    views_by_module: Dict[str, List[ViewFunction]] = {}
    for view in all_views:
        module = view.module_path.rsplit('.', 1)[0] if '.' in view.module_path else view.module_path
        if module not in views_by_module:
            views_by_module[module] = []
        views_by_module[module].append(view)

    # Generate models grouped by module
    for module in sorted(views_by_module.keys()):
        output_lines.append(f"# --- {module} ---")
        output_lines.append("")

        for view in views_by_module[module]:
            model = generate_pysa_model(view)
            output_lines.append(model)
            output_lines.append("")

    # Write output file
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    return len(all_views), all_views


def print_summary(views: List[ViewFunction]) -> None:
    """Print a summary of discovered views."""
    print("\n" + "=" * 60)
    print("VIEW DISCOVERY SUMMARY")
    print("=" * 60)

    # Group by module
    modules: Dict[str, int] = {}
    for view in views:
        module = view.module_path.rsplit('.', 1)[0]
        modules[module] = modules.get(module, 0) + 1

    print(f"\nTotal view functions: {len(views)}")
    print(f"Modules with views: {len(modules)}")
    print("\nViews per module:")

    for module in sorted(modules.keys()):
        print(f"  {module}: {modules[module]}")

    # List views with vulnerability comments
    vuln_views = [v for v in views if v.docstring and ('VULNERABILITY' in v.docstring.upper() or 'CWE-' in v.docstring)]

    if vuln_views:
        print(f"\nViews with vulnerability documentation: {len(vuln_views)}")
        for view in vuln_views:
            print(f"  - {view.module_path}.{view.name}")


def main():
    """Main entry point."""
    # Determine paths
    script_dir = Path(__file__).parent.resolve()
    pysa_dir = script_dir.parent
    source_dir = pysa_dir / ".." / ".." / "vulnerable-app"
    output_file = pysa_dir / "models" / "vulnshop_auto.pysa"

    print("=" * 60)
    print("PYSA MODEL GENERATOR FOR VULNSHOP")
    print("=" * 60)
    print(f"\nSource directory: {source_dir.resolve()}")
    print(f"Output file: {output_file.resolve()}")

    # Generate models
    count, views = generate_models(str(source_dir.resolve()), str(output_file))

    if count > 0:
        print(f"\nSuccessfully generated {count} view models")
        print_summary(views)
        print(f"\nOutput written to: {output_file}")
    else:
        print("\nNo view functions found to generate models for")
        sys.exit(1)


if __name__ == "__main__":
    main()
