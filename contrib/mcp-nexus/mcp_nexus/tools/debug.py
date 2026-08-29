"""Code debugging, linting, and analysis tools."""

from __future__ import annotations

import json
import shlex

from mcp.server.fastmcp import FastMCP

from mcp_nexus.server import get_pool


def register(mcp: FastMCP):

    @mcp.tool()
    async def lint_python(path: str, fix: bool = False) -> str:
        """Run Python linter (ruff or flake8) on a file or directory."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            ruff = await conn.run_full("which ruff 2>/dev/null")
            if ruff.ok:
                cmd = f"ruff check {'--fix' if fix else ''} {shlex.quote(path)} 2>&1"
            else:
                flake8 = await conn.run_full("which flake8 2>/dev/null")
                if flake8.ok:
                    cmd = f"flake8 {shlex.quote(path)} 2>&1"
                else:
                    return json.dumps({"error": "No Python linter found (install ruff or flake8)"})

            result = await conn.run_full(cmd, timeout=60)
            issues = result.stdout.strip()
            return json.dumps(
                {
                    "path": path,
                    "linter": "ruff" if ruff.ok else "flake8",
                    "fixed": fix and ruff.ok,
                    "issues": issues if issues else "(clean — no issues found)",
                    "exit_code": result.exit_code,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def typecheck(path: str) -> str:
        """Run Python type checker (mypy or pyright) on a file or directory."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            mypy = await conn.run_full("which mypy 2>/dev/null")
            if mypy.ok:
                cmd = f"mypy {shlex.quote(path)} 2>&1"
            else:
                pyright = await conn.run_full("which pyright 2>/dev/null")
                if pyright.ok:
                    cmd = f"pyright {shlex.quote(path)} 2>&1"
                else:
                    return json.dumps({"error": "No type checker found (install mypy or pyright)"})

            result = await conn.run_full(cmd, timeout=120)
            return json.dumps(
                {
                    "path": path,
                    "checker": "mypy" if mypy.ok else "pyright",
                    "output": result.stdout.strip(),
                    "exit_code": result.exit_code,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def syntax_check(path: str) -> str:
        """Check file syntax without executing."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            ext_cmd = f"echo {shlex.quote(path)} | rev | cut -d. -f1 | rev"
            ext_result = await conn.run(ext_cmd, timeout=5)
            ext = ext_result.strip().lower()

            checks = {
                "py": f'python3 -c "import ast; ast.parse(open({shlex.quote(path)}).read())" 2>&1',
                "js": f"node --check {shlex.quote(path)} 2>&1",
                "mjs": f"node --check {shlex.quote(path)} 2>&1",
                "json": f'python3 -c "import json; json.load(open({shlex.quote(path)}))" 2>&1',
                "yaml": f'python3 -c "import yaml; yaml.safe_load(open({shlex.quote(path)}))" 2>&1',
                "yml": f'python3 -c "import yaml; yaml.safe_load(open({shlex.quote(path)}))" 2>&1',
                "sh": f"bash -n {shlex.quote(path)} 2>&1",
                "bash": f"bash -n {shlex.quote(path)} 2>&1",
                "xml": f'python3 -c "import xml.etree.ElementTree as ET; ET.parse({shlex.quote(path)})" 2>&1',
                "html": (
                    "python3 -c "
                    f'"from html.parser import HTMLParser; HTMLParser().feed(open({shlex.quote(path)}).read())" 2>&1'
                ),
            }

            if ext not in checks:
                return json.dumps({"error": f"No syntax checker for .{ext} files", "supported": list(checks.keys())})

            result = await conn.run_full(checks[ext], timeout=30)
            return json.dumps(
                {
                    "path": path,
                    "language": ext,
                    "valid": result.exit_code == 0,
                    "errors": result.stdout.strip() if result.exit_code != 0 else None,
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def find_todos(path: str = ".", pattern: str = "TODO|FIXME|HACK|BUG|XXX") -> str:
        """Find TODO-like markers in code."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            rg = await conn.run_full("which rg 2>/dev/null")
            if rg.ok:
                cmd = f"rg -n '({pattern})' {shlex.quote(path)} --max-count 200 2>&1"
            else:
                cmd = f"grep -rn -E '({pattern})' {shlex.quote(path)} 2>/dev/null | head -200"
            result = await conn.run_full(cmd, timeout=30)
            matches = result.stdout.strip()
            count = len(matches.split("\n")) if matches else 0
            return json.dumps(
                {"path": path, "pattern": pattern, "count": count, "matches": matches if matches else "(none found)"}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def code_symbols(path: str, symbol_type: str = "all") -> str:
        """Find function, class, and import definitions in source code."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            patterns = {
                "all": r"(^\s*(def |class |async def |function |const |let |var |export |import ))",
                "function": r"(^\s*(def |async def |function ))",
                "class": r"(^\s*class )",
                "import": r"(^\s*(import |from .+ import |require\(|const .+ = require))",
            }
            pat = patterns.get(symbol_type, patterns["all"])

            rg = await conn.run_full("which rg 2>/dev/null")
            if rg.ok:
                cmd = f"rg -n '{pat}' {shlex.quote(path)} --max-count 500 2>&1"
            else:
                cmd = f"grep -rn -E '{pat}' {shlex.quote(path)} 2>/dev/null | head -500"

            result = await conn.run_full(cmd, timeout=30)
            return json.dumps(
                {
                    "path": path,
                    "symbol_type": symbol_type,
                    "symbols": result.stdout.strip() if result.stdout.strip() else "(no symbols found)",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def compare_files(file_a: str, file_b: str, context_lines: int = 3) -> str:
        """Compare two files and show differences."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            cmd = f"diff -u --color=never -U {context_lines} {shlex.quote(file_a)} {shlex.quote(file_b)} 2>&1"
            result = await conn.run_full(cmd, timeout=30)
            if result.exit_code == 0:
                return json.dumps({"identical": True, "file_a": file_a, "file_b": file_b})
            return json.dumps({"identical": False, "file_a": file_a, "file_b": file_b, "diff": result.stdout[:50000]})
        finally:
            pool.release(conn)

    @mcp.tool()
    async def find_errors(
        path: str = "/var/log", pattern: str = "error|exception|traceback|fatal|panic", lines: int = 100
    ) -> str:
        """Search logs or code for error patterns."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            rg = await conn.run_full("which rg 2>/dev/null")
            if rg.ok:
                cmd = f"rg -in '({pattern})' {shlex.quote(path)} --max-count {lines} 2>&1"
            else:
                cmd = f"grep -rin -E '({pattern})' {shlex.quote(path)} 2>/dev/null | head -{lines}"
            result = await conn.run_full(cmd, timeout=60)
            return json.dumps(
                {
                    "path": path,
                    "pattern": pattern,
                    "matches": result.stdout.strip() if result.stdout.strip() else "(no errors found)",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def python_trace(file: str, function: str = "") -> str:
        """Analyze Python file for common undefined or unused symbol issues."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            pyflakes = await conn.run_full("which pyflakes 2>/dev/null")
            if pyflakes.ok:
                cmd = f"pyflakes {shlex.quote(file)} 2>&1"
                result = await conn.run_full(cmd, timeout=30)
                output = result.stdout.strip()
            else:
                cmd = (
                    f'python3 -c "'
                    f"import ast; "
                    f"tree = ast.parse(open({shlex.quote(file)}).read()); "
                    f"names = {{n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}}; "
                    f"imports = {{a.name for n in ast.walk(tree) "
                    f"if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}}; "
                    f"print('Imports:', sorted(imports)); print('Names used:', len(names))\" 2>&1"
                )
                result = await conn.run_full(cmd, timeout=30)
                output = result.stdout.strip()

            if function:
                func_cmd = f"grep -n 'def {function}' {shlex.quote(file)} 2>&1"
                func_result = await conn.run_full(func_cmd, timeout=10)
                output += f"\n\nFunction '{function}' found at:\n{func_result.stdout.strip()}"

            return json.dumps(
                {"file": file, "analysis": output if output else "(no issues detected)", "exit_code": result.exit_code}
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def find_references(symbol: str, path: str = ".", word_boundary: bool = True) -> str:
        """Search for references to a symbol across a codebase."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            pattern = rf"\b{symbol}\b" if word_boundary else symbol
            rg = await conn.run_full("which rg 2>/dev/null")
            if rg.ok:
                cmd = f"rg -n '{pattern}' {shlex.quote(path)} --max-count 500 2>&1"
            else:
                cmd = f"grep -rn -E '{pattern}' {shlex.quote(path)} 2>/dev/null | head -500"
            result = await conn.run_full(cmd, timeout=30)
            return json.dumps(
                {
                    "symbol": symbol,
                    "path": path,
                    "matches": result.stdout.strip() if result.stdout.strip() else "(none found)",
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def run_tests(path: str = ".", command: str = "", fail_fast: bool = False) -> str:
        """Run a detected or explicit test command."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if command:
                test_command = command
                detected = "explicit"
            else:
                if await conn.file_exists(f"{path}/pytest.ini") or await conn.file_exists(f"{path}/pyproject.toml"):
                    test_command = "pytest"
                    detected = "pytest"
                elif await conn.file_exists(f"{path}/package.json"):
                    test_command = "npm test"
                    detected = "npm"
                else:
                    return json.dumps({"error": "Could not infer a test runner; provide command explicitly"})
            if fail_fast and detected == "pytest":
                test_command += " -x"
            result = await conn.run_full(f"cd {shlex.quote(path)} && {test_command}", timeout=600)
            return json.dumps(
                {
                    "runner": detected,
                    "command": test_command,
                    "ok": result.ok,
                    "output": (result.stdout + result.stderr).strip()[-40000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def format_code(path: str = ".", check_only: bool = True) -> str:
        """Run an available formatter for Python or JS projects."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            if (await conn.run_full("which ruff 2>/dev/null")).ok:
                command = f"ruff format {'--check' if check_only else ''} {shlex.quote(path)}"
                formatter = "ruff"
            elif (await conn.run_full("which black 2>/dev/null")).ok:
                command = f"black {'--check' if check_only else ''} {shlex.quote(path)}"
                formatter = "black"
            elif (await conn.run_full("which prettier 2>/dev/null")).ok:
                flag = "--check" if check_only else "--write"
                command = f"prettier {flag} {shlex.quote(path)}"
                formatter = "prettier"
            else:
                return json.dumps({"error": "No supported formatter found (ruff, black, prettier)"})
            result = await conn.run_full(command, timeout=180)
            return json.dumps(
                {
                    "formatter": formatter,
                    "check_only": check_only,
                    "ok": result.ok,
                    "output": (result.stdout + result.stderr).strip()[-20000:],
                }
            )
        finally:
            pool.release(conn)

    @mcp.tool()
    async def stack_traces(path: str = "/var/log", lines: int = 80) -> str:
        """Search for stack traces and return nearby context."""
        pool = get_pool()
        conn = await pool.acquire()
        try:
            rg = await conn.run_full("which rg 2>/dev/null")
            pattern = "Traceback|Exception:|panic:|stack trace|Segmentation fault"
            if rg.ok:
                cmd = f"rg -n -C 3 '({pattern})' {shlex.quote(path)} --max-count {lines} 2>&1"
            else:
                cmd = f"grep -rin -E '({pattern})' {shlex.quote(path)} 2>/dev/null | head -{lines}"
            result = await conn.run_full(cmd, timeout=60)
            return json.dumps(
                {"path": path, "stack_traces": result.stdout.strip() if result.stdout.strip() else "(none found)"}
            )
        finally:
            pool.release(conn)
