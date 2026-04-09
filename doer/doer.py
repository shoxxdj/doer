#!/usr/bin/env python3
"""
doer - A YAML-driven workflow executor for security auditing and automation.

Variables defined in the workflow 'vars' section can be passed as CLI arguments
(--VAR=value) or set as environment variables. Required variables must be provided;
optional variables fall back to defaults or are skipped.
"""

VERSION = "0.2.0"
VERSION_NAME = "Cleaned up"
CREDITS_STRING = "shoxxdj, claude.ai (for cleaning)"

import ast
import importlib.util
import json
import logging
import operator
import os
import random
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import yaml
import chalk

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set




# ---------------------------------------------------------------------------
# Operators used in WHEN expressions
# ---------------------------------------------------------------------------
OPS: Dict[str, Callable] = {
    "==": operator.eq,
    "!=": operator.ne,
    ">":  operator.gt,
    "<":  operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
}


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------
def print_banner() -> None:
    colors = [
        chalk.red, chalk.green, chalk.yellow,
        chalk.blue, chalk.magenta, chalk.cyan, chalk.white,
    ]
    color = random.choice(colors)
    banner = f"""
    ██████╗  ██████╗ ███████╗██████╗
    ██╔══██╗██╔═══██╗██╔════╝██╔══██╗
    ██║  ██║██║   ██║█████╗  ██████╔╝
    ██║  ██║██║   ██║██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝███████╗██║  ██║
    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝

        "I do what the template says."
         Version : {VERSION}
         Name    : {VERSION_NAME}
         Credits : {CREDITS_STRING}
    """
    print(color(banner))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class ErrorHandling(Enum):
    """Strategy for handling step failures."""
    STOP     = "stop"      # Abort the workflow on any error
    CONTINUE = "continue"  # Keep running despite errors
    SKIP     = "skip"      # Log the error and skip the failing step


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "DEBUG":    chalk.blue,
        "INFO":     chalk.green,
        "WARNING":  chalk.yellow,
        "ERROR":    chalk.red,
        "CRITICAL": chalk.white,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelname)
        if color:
            record.levelname = color(record.levelname)
        return super().format(record)


def setup_logging(debug: bool = False) -> logging.Logger:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"workflow_{timestamp}.log"

    logger = logging.getLogger("doer")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    file_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console_fmt = ColoredFormatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(file_fmt)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_fmt)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.info(f"Log file: {log_file}")
    return logger


# ---------------------------------------------------------------------------
# WorkflowExecutor
# ---------------------------------------------------------------------------
class WorkflowExecutor:
    """
    Loads a YAML workflow and executes its steps sequentially.

    Result storage convention
    -------------------------
    Step results are stored in ``self.results`` under a *plain* string key
    (without a leading ``$``).  The ``$`` prefix is only used in workflow
    YAML when *referencing* a result.  This single convention avoids the
    inconsistency that existed in the original code.
    """

    def __init__(
        self,
        workflow_file: str,
        options: Any,
        error_handling: ErrorHandling = ErrorHandling.STOP,
    ) -> None:
        self.workflow_file = workflow_file
        self.workflow: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {}   # plain keys, no leading '$'
        self.variables: Dict[str, str] = {}
        self.error_handling = error_handling
        self.errors: List[Dict[str, str]] = []
        self.options = options
        self.logger = setup_logging(getattr(options, "debug", False))

    # ------------------------------------------------------------------
    # Workflow loading
    # ------------------------------------------------------------------
    def load_workflow(self) -> None:
        """Load and parse the YAML workflow file."""
        try:
            with open(self.workflow_file, "r", encoding="utf-8") as fh:
                self.workflow = yaml.safe_load(fh)
            self.logger.info(
                f"✓ Workflow '{self.workflow.get('name', 'unnamed')}' loaded"
            )
        except FileNotFoundError:
            self.logger.error(f"✗ File '{self.workflow_file}' not found")
            sys.exit(1)
        except yaml.YAMLError as exc:
            self.logger.error(f"✗ YAML parsing error: {exc}")
            sys.exit(1)

    # ------------------------------------------------------------------
    # Variable management
    # ------------------------------------------------------------------
    def find_required_variables(self) -> tuple:
        """
        Read the 'vars' section of the workflow.

        Returns (required_vars, optional_vars) as lowercase string sets.
        """
        required_vars: Set[str] = set()
        optional_vars: Set[str] = set()

        vars_section = self.workflow.get("vars", {})

        required_list = vars_section.get("required", [])
        if isinstance(required_list, list):
            required_vars = {v.lower() for v in required_list if isinstance(v, str)}
            if required_vars:
                self.logger.debug(f"Required vars: {', '.join(sorted(required_vars))}")

        optional_list = vars_section.get("optional", [])
        if isinstance(optional_list, list):
            optional_vars = {v.lower() for v in optional_list if isinstance(v, str)}
            if optional_vars:
                self.logger.debug(f"Optional vars: {', '.join(sorted(optional_vars))}")

        return required_vars, optional_vars

    def load_variables_from_options(
        self, required_vars: Set[str], optional_vars: Set[str]
    ) -> None:
        """
        Populate ``self.variables`` from environment variables first,
        then from CLI arguments (which take precedence).
        """
        all_vars = required_vars | optional_vars

        for var in all_vars:
            env_value = os.getenv(var) or os.getenv(var.upper())
            if env_value:
                self.variables[var] = env_value
                self.logger.debug(f"Variable '{var}' loaded from environment")

        cli_vars: Dict[str, str] = getattr(self.options, "variables", {}) or {}
        for name, value in cli_vars.items():
            self.variables[name] = value
            self.logger.debug(f"Variable '{name}' loaded from CLI")

    def check_missing_variables(self, required_vars: Set[str]) -> List[str]:
        """Return the list of required variables that are not yet set."""
        return [v for v in required_vars if not self.variables.get(v)]

    # ------------------------------------------------------------------
    # Variable substitution
    # ------------------------------------------------------------------
    def substitute_variables(self, text: str) -> str:
        """
        Replace all ``$VAR``, ``${VAR}``, and ``$result.property`` references
        in *text* with their current values.
        """
        if not isinstance(text, str):
            return text

        # 1. User-defined variables
        for var, value in self.variables.items():
            text = text.replace(f"${var}", str(value))
            text = text.replace(f"${var.upper()}", str(value))
            text = text.replace(f"${{{var}}}", str(value))

        # 2. Fallback for $SCRIPTS
        if "$SCRIPTS" in text:
            self.logger.info(
                "Replacing $SCRIPTS with ./scripts "
                "(SCRIPTS optional variable not set)"
            )
            text = text.replace("$SCRIPTS", "./scripts")

        # 3. result.property dot-access
        text = self._substitute_dot_properties(text)

        # 4. Plain result variables
        for key, value in self.results.items():
            text = text.replace(f"${key}", str(value))
            text = text.replace(f"${{{key}}}", str(value))

        return text

    def _substitute_dot_properties(self, text: str) -> str:
        """Replace ``$var.property`` (and nested ``$a.b.c``) references."""
        pattern = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_.]+)")

        for match in pattern.finditer(text):
            var_name, prop_path = match.group(1), match.group(2)
            full_ref = f"${var_name}.{prop_path}"

            value = self._resolve_path(var_name, prop_path)
            if value is not None:
                if isinstance(value, (dict, list)):
                    replacement = json.dumps(value, indent=2, ensure_ascii=False)
                else:
                    replacement = str(value)
                text = text.replace(full_ref, replacement)
            else:
                self.logger.warning(f"Variable '{full_ref}' not found")

        return text

    def _resolve_path(self, root_key: str, dot_path: str) -> Optional[Any]:
        """
        Traverse ``self.results[root_key]`` following *dot_path*.
        Returns ``None`` if any segment is missing.
        """
        if root_key not in self.results:
            return None

        value: Any = self.results[root_key]

        for part in dot_path.split("."):
            value = self._maybe_parse(value)
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None

        return value

    @staticmethod
    def _maybe_parse(value: Any) -> Any:
        """Try to parse a string value as JSON or Python literal."""
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            return ast.literal_eval(value)
        except Exception:
            pass
        return value

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------
    def handle_error(self, step_name: str, error: Exception) -> bool:
        """
        Record an error and decide whether to continue.

        Returns True if execution should continue, False to stop.
        """
        self.errors.append({"step": step_name, "error": str(error)})

        if self.error_handling == ErrorHandling.STOP:
            self.logger.error(f"✗ Error in '{step_name}': {error} — stopping")
            return False
        elif self.error_handling == ErrorHandling.CONTINUE:
            self.logger.warning(f"⚠ Error in '{step_name}': {error} — continuing")
            return True
        else:  # SKIP
            self.logger.warning(f"⚠ Error in '{step_name}': {error} — skipping step")
            return True

    # ------------------------------------------------------------------
    # Step execution
    # ------------------------------------------------------------------
    def execute_step(self, step_name: str) -> bool:
        """Dispatch a named step to the appropriate handler."""
        if step_name not in self.workflow:
            return self.handle_error(
                step_name,
                KeyError(f"Step '{step_name}' not found in workflow"),
            )

        step_config = self.workflow[step_name]
        step_type = step_config.get("type", "unknown")

        if step_type == "shell":
            return self.execute_shell_command(step_name, step_config)

        return self.handle_error(
            step_name,
            ValueError(f"Unknown step type '{step_type}' in step '{step_name}'"),
        )

    def execute_shell_command(
        self, step_name: str, step_config: Dict[str, Any]
    ) -> bool:
        """Run a shell command defined in a workflow step."""
        command = self.substitute_variables(step_config.get("command_line", ""))
        result_var: Optional[str] = step_config.get("result")
        timeout: int = step_config.get("timeout", 300)

        self.logger.info(f"▶ Running '{step_name}'")
        self.logger.debug(f"  Command: {command}")

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            if result_var:
                # Always store under plain key (no '$' prefix)
                self.results[result_var] = stdout if proc.returncode == 0 else stderr
                self.logger.debug(f"  Result stored as '{result_var}'")

            if proc.returncode != 0:
                self.logger.warning(
                    f"  ⚠ Command exited with code {proc.returncode}"
                )
                if self.error_handling == ErrorHandling.STOP:
                    self.logger.error(f"  stderr: {stderr}")
                    self.logger.error(f"  stdout: {stdout}")
                    raise subprocess.CalledProcessError(proc.returncode, command)
            else:
                self.logger.info("  ✓ Command succeeded")
                if stdout and getattr(self.options, "debug", False):
                    self.logger.debug(f"  Output: {stdout}")

            return proc.returncode == 0

        except subprocess.TimeoutExpired:
            return self.handle_error(
                step_name,
                TimeoutError(f"Command timed out after {timeout}s"),
            )
        except Exception as exc:
            return self.handle_error(step_name, exc)

    # ------------------------------------------------------------------
    # WHEN expression evaluation
    # ------------------------------------------------------------------
    def evaluate_when(self, expression: str) -> bool:
        """
        Evaluate a WHEN guard expression, e.g.:

            output_analyze_nmap.condition == "web_only"
            output_analyze_nmap.total_open_ports > 3

        The left-hand side is resolved from ``self.results`` using dot notation.
        """
        try:
            parts = expression.split(maxsplit=2)
            if len(parts) != 3:
                self.logger.error(
                    f"WHEN: malformed expression '{expression}' "
                    "(expected: <left> <op> <right>)"
                )
                return False

            left, op_str, right_raw = parts

            segments = left.lstrip("$").split(".")
            root_key = segments[0]
            dot_path = ".".join(segments[1:]) if len(segments) > 1 else None

            if dot_path:
                lhs = self._resolve_path(root_key, dot_path)
            elif root_key in self.results:
                lhs = self._maybe_parse(self.results[root_key])
            else:
                self.logger.debug(f"WHEN: '{left}' not found in results")
                return False

            if lhs is None:
                self.logger.debug(f"WHEN: '{left}' resolved to None")
                return False

            # Normalise right-hand side
            rhs: Any = right_raw.strip()
            if rhs.startswith('"') and rhs.endswith('"'):
                rhs = rhs[1:-1]
            elif rhs.lstrip("-").isdigit():
                rhs = int(rhs)
            elif rhs.lower() in ("true", "false"):
                rhs = rhs.lower() == "true"
            else:
                try:
                    rhs = float(rhs)
                except ValueError:
                    pass

            if op_str not in OPS:
                self.logger.error(f"WHEN: unsupported operator '{op_str}'")
                return False

            return OPS[op_str](lhs, rhs)

        except Exception as exc:
            self.logger.error(f"WHEN evaluation error for '{expression}': {exc}")
            return False

    def run_custom_output(self) -> None:
        """
        Dynamically load a user-supplied Python module and call its ``main``
        function, passing this executor as the sole argument.
        """
        path = getattr(self.options, "custom_output", None)
        if not path:
            return

        module_path = Path(path)

        if not module_path.exists():
            self.logger.error(f"✗ custom_output file '{path}' not found")
            sys.exit(1)

        if module_path.suffix != ".py":
            self.logger.error("✗ custom_output must be a .py file")
            sys.exit(1)

        try:
            spec = importlib.util.spec_from_file_location("custom_output", module_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot load module from '{path}'")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]

            if not hasattr(module, "main"):
                self.logger.error(
                    "✗ custom_output module must expose a 'main(executor)' function"
                )
                sys.exit(1)

            self.logger.info(f"✓ custom_output module loaded from '{path}'")
            module.main(self)

        except SystemExit:
            raise
        except Exception as exc:
            self.logger.error(f"✗ Error loading custom_output module: {exc}")
            sys.exit(1)

    # ------------------------------------------------------------------
    # nmap formatting helper
    # ------------------------------------------------------------------
    def _format_nmap_file(self, nmap_path: str) -> str:
        """Read an nmap output file and render it as readable text."""
        path = Path(nmap_path)
        if not path.exists():
            self.logger.warning(f"nmap file '{nmap_path}' not found")
            return f"[nmap file '{nmap_path}' not found]"

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            self.logger.error(f"Cannot read nmap file '{nmap_path}': {exc}")
            return f"[Cannot read nmap file '{nmap_path}']"

        if not content.strip().startswith("<?xml"):
            return content

        try:
            root = ET.fromstring(content)
            lines: List[str] = []
            for host in root.findall(".//host"):
                addr = host.find(".//address")
                if addr is not None:
                    lines.append(f"\nHost: {addr.get('addr')}")
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        pid    = port.get("portid")
                        proto  = port.get("protocol")
                        svc    = port.find("service")
                        svcname = svc.get("name", "unknown") if svc is not None else "unknown"
                        lines.append(f"  - {pid}/{proto}: {svcname}")
            return "\n".join(lines) if lines else "[No open ports found]"
        except ET.ParseError as exc:
            self.logger.error(f"XML parsing error for '{nmap_path}': {exc}")
            return content

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def run(self) -> int:
        """
        Execute the full workflow. Returns 0 on success, 1 on failure.
        """
        self.load_workflow()

        required_vars, optional_vars = self.find_required_variables()
        self.load_variables_from_options(required_vars, optional_vars)

        missing = self.check_missing_variables(required_vars)
        if missing:
            self.logger.error(
                f"✗ Missing required variables: {', '.join(sorted(missing))}"
            )
            hints = " ".join(f"--{v.lower()}=<value>" for v in sorted(missing))
            self.logger.error(f"  Provide them via CLI: {hints}")
            return 1

        if self.variables:
            summary = ", ".join(
                f"{k}={v} ({'required' if k in required_vars else 'optional'})"
                for k, v in sorted(self.variables.items())
            )
            self.logger.info(f"Variables loaded: {summary}")

        steps: List[str] = self.workflow.get("steps", [])
        if not steps:
            self.logger.error("✗ No steps defined in workflow")
            return 1

        self.logger.info("=" * 60)
        self.logger.info(f"WORKFLOW START: {self.workflow.get('name', 'unnamed')}")
        self.logger.info("=" * 60)
        self.logger.info(f"Steps: {', '.join(steps)}")
        self.logger.info(f"Error handling: {self.error_handling.value}")

        success = True
        for step_name in steps:
            if step_name == "generate_text":
                if getattr(self.options, "custom_output", None):
                    self.run_custom_output()
                else:
                    self.options.custom_output="custom_output/builtin.py"
                    self.run_custom_output()
                    #print(self.generate_text(self.workflow["generate_text"]))
                continue

            ok = self.execute_step(step_name)
            if not ok and self.error_handling == ErrorHandling.STOP:
                success = False
                break

        self.logger.info("=" * 60)
        self.logger.info("WORKFLOW END")
        self.logger.info("=" * 60)

        if self.errors:
            self.logger.warning(f"⚠ {len(self.errors)} error(s) encountered:")
            for err in self.errors:
                self.logger.warning(f"  - {err['step']}: {err['error']}")

        return 0 if success else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_variable_args(args_list: List[str]) -> Dict[str, str]:
    """
    Parse ``--VAR=value`` entries from *args_list*.
    Keys are normalised to lowercase.
    """
    variables: Dict[str, str] = {}
    pattern = re.compile(r"^--([a-zA-Z_][a-zA-Z0-9_]*)=(.+)")
    for arg in args_list:
        m = pattern.match(arg)
        if m:
            variables[m.group(1).lower()] = m.group(2)
    return variables


def main() -> None:
    """CLI entry point."""
    import argparse

    SYSTEM_FLAGS = {"--error-handling", "--debug", "--custom-output"}

    known_args: List[str] = []
    variable_args: List[str] = []

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg.startswith("--") and "=" in arg:
            flag = arg.split("=", 1)[0]
            if flag in SYSTEM_FLAGS:
                known_args.append(arg)
            else:
                variable_args.append(arg)
        elif arg in SYSTEM_FLAGS:
            known_args.append(arg)
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
                i += 1
                known_args.append(sys.argv[i])
        else:
            known_args.append(arg)

        i += 1

    parser = argparse.ArgumentParser(
        description="Execute a YAML-defined workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Variables
---------
Declare them in the workflow under 'vars':

  vars:
    required:
      - URL
      - OUTPUT
    optional:
      - SCRIPTS

Pass values via CLI (--URL=example.com) or as environment variables.

Custom output
-------------
Supply --custom-output=my_output.py with a module exposing main(executor).

Examples
--------
  %(prog)s workflow.yaml --url=example.com --output=scan.xml
  %(prog)s workflow.yaml --error-handling continue --url=test.com
  %(prog)s workflow.yaml --custom-output=my_output.py --url=test.com
  URL=example.com %(prog)s workflow.yaml
        """,
    )

    parser.add_argument("workflow_file", nargs="?", help="Path to the YAML workflow")
    parser.add_argument(
        "--error-handling",
        choices=["stop", "continue", "skip"],
        default="stop",
        help="Error strategy (default: stop)",
    )
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")
    parser.add_argument(
        "--custom-output",
        type=str,
        metavar="FILE",
        help="Python module with a main(executor) function for custom output",
    )

    try:
        args = parser.parse_args(known_args)
    except SystemExit:
        sys.exit(1)

    args.variables = parse_variable_args(variable_args)

    if args.debug:
        print(f"Debug — workflow_file : {args.workflow_file}")
        print(f"Debug — variables     : {args.variables}")
        print(f"Debug — custom_output : {args.custom_output}")

    if not args.workflow_file:
        print_banner()
        print("✗ Error: a YAML workflow file is required")
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.workflow_file):
        print(f"✗ File '{args.workflow_file}' not found")
        sys.exit(1)

    if not args.workflow_file.endswith((".yaml", ".yml")):
        print("✗ Workflow file must have a .yaml or .yml extension")
        sys.exit(1)

    error_handling = ErrorHandling(args.error_handling)
    executor = WorkflowExecutor(args.workflow_file, args, error_handling)
    sys.exit(executor.run())


if __name__ == "__main__":
    main()
