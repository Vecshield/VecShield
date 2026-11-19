"""Rebuild AgentDojo's injected tool outputs without running AgentDojo.

AgentDojo places an attacker's goal into the data an agent's tools return (an
email body, a file, a calendar entry, a web page), wrapped by an attack
template. The pieces are all in its repository as data: environments and
injection points in YAML, goals and templates as string constants in Python.
This module reads the YAML with ``safe_load`` and the constants with ``ast``.
Nothing from the repository is imported or executed.

Choices made here, not by AgentDojo: the user is named "Emma Johnson" (its
default) and the model "AI assistant" (AgentDojo substitutes the name of the
model under test); a document is the JSON of the record an injection point
sits in, or the string itself when it is not inside a record; templates with
placeholders beyond ``{goal}``, ``{user}`` and ``{model}`` are skipped.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Iterator

USER, MODEL = "Emma Johnson", "AI assistant"
_FIELDS = re.compile(r"\{([A-Za-z_]+)\}")


def _string(node: ast.AST, names: dict[str, str]) -> str | None:
    """The value of a string expression built from constants, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name) \
                    and value.value.id in names:
                parts.append(names[value.value.id])
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _string(node.left, names), _string(node.right, names)
        return None if left is None or right is None else left + right
    return None


def goals(path: Path) -> list[str]:
    """Every ``GOAL`` an injection task declares, with its constants filled in."""
    out = []
    for cls in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(cls, ast.ClassDef):
            continue
        names: dict[str, str] = {}
        for stmt in cls.body:
            target = None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name):
                target, value = stmt.targets[0].id, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) \
                    and stmt.value is not None:
                target, value = stmt.target.id, stmt.value
            if target is None:
                continue
            text = _string(value, names)
            if text is None:
                continue
            names[target] = text
            if target == "GOAL":
                out.append(text)
    return out


def templates(path: Path) -> dict[str, str]:
    """``{attack name: template}`` for attacks whose template is a constant."""
    out: dict[str, str] = {}
    for cls in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(cls, ast.ClassDef):
            continue
        name = template = None
        for node in ast.walk(cls):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id == "name":
                    name = _string(node.value, {})
                elif node.targets[0].id == "_JB_STRING":
                    template = _string(node.value, {})
            elif isinstance(node, ast.Call) and template is None:
                for arg in node.args:
                    text = _string(arg, {})
                    if text and "{goal}" in text:
                        template = text
        if name and template and set(_FIELDS.findall(template)) <= {"goal", "user", "model"}:
            out[name] = template
    return out


def _records(node: Any, pattern: re.Pattern) -> Iterator[tuple[str, Any]]:
    """``(string with an injection point, the record it sits in)``."""
    if isinstance(node, dict):
        scalars = all(not isinstance(v, (dict, list)) for v in node.values())
        for value in node.values():
            if isinstance(value, str) and pattern.search(value):
                yield value, (node if scalars and len(node) > 1 else None)
            else:
                yield from _records(value, pattern)
    elif isinstance(node, list):
        for value in node:
            if isinstance(value, str) and pattern.search(value):
                yield value, None
            else:
                yield from _records(value, pattern)


def documents(environment: Any, vectors: dict[str, dict]) -> list[dict]:
    """Each injection point as a document template with its benign defaults.

    An injection point is ``{name}`` for a name declared in the suite's
    ``injection_vectors.yaml``.
    """
    pattern = re.compile(r"\{(" + "|".join(map(re.escape, vectors)) + r")\}")
    defaults = {name: str((spec or {}).get("default") or "").replace("\\n", "\n")
                .replace("\\t", "\t") for name, spec in vectors.items()}

    def fill(text: str, values: dict[str, str]) -> str:
        return pattern.sub(lambda m: values.get(m.group(1), ""), text)

    out = []
    for leaf, record in _records(environment, pattern):
        for point in dict.fromkeys(pattern.findall(leaf)):
            def render(value: str, leaf=leaf, record=record, point=point) -> str:
                values = {**defaults, point: value}
                if record is None:
                    return fill(leaf, values)
                return json.dumps({k: (fill(v, values) if isinstance(v, str) else v)
                                   for k, v in record.items()},
                                  ensure_ascii=False, indent=1, default=str)
            out.append({"point": point, "render": render, "clean": render(defaults[point])})
    return out


def render_attack(template: str, goal: str) -> str:
    return template.replace("{goal}", goal).replace("{user}", USER).replace("{model}", MODEL)
