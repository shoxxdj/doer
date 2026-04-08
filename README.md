# doer

> *"I do what the template says."*

**doer** is a YAML-driven workflow executor designed for security auditing and
network reconnaissance automation.  You describe a sequence of shell commands,
variable substitutions, and conditional output blocks in a single YAML file;
`doer` runs them in order and optionally produces a formatted text report.

---

## Installation

Requires **Python ≥ 3.13** and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/shoxxdj/doer.git
cd doer
poetry install
```

---

## Quick start

```bash
# Run the built-in network mapping workflow
poetry run doer workflows/network_mapping.yaml --url=example.com

# With explicit SCRIPTS path
poetry run doer workflows/network_mapping.yaml \
    --url=example.com \
    --scripts=/opt/doer/scripts

# Continue on errors instead of stopping
poetry run doer workflows/network_mapping.yaml \
    --url=example.com \
    --error-handling=continue

# Debug mode (verbose output)
poetry run doer workflows/network_mapping.yaml \
    --url=example.com \
    --debug

# Custom output module
poetry run doer workflows/network_mapping.yaml \
    --url=example.com \
    --custom-output=custom_output/text.py

# Variables can also come from the environment
URL=example.com poetry run doer workflows/network_mapping.yaml
```

---

## Workflow YAML format

```yaml
name: my workflow        # human-readable name

# Declare variables used in command lines
vars:
  required:
    - URL                # must be provided via CLI or env
  optional:
    - SCRIPTS            # defaults to ./scripts if omitted

# Ordered list of step names to execute
steps:
  - step_one
  - step_two
  - generate_text        # special step: produces the final report

# Step definitions
step_one:
  type: shell
  command_line: echo "hello $URL"
  result: output_step_one   # stores stdout (plain key, no '$')
  timeout: 60               # optional, default 300s

step_two:
  type: shell
  command_line: some_tool $output_step_one
  result: output_step_two

# generate_text produces the final report to stdout
generate_text:
  steps:
    - content:
        - type: text
          value: "Report for $URL"

    - content:
        - type: extract
          value: $output_step_one        # insert raw result

    - when: '$output_step_two.condition == "critical"'
      content:
        - type: text
          value: "Critical issues found!"
        - type: extract
          value: $output_step_two.details

    - content:
        - type: nmap
          value: $URL.nmap.xml           # renders an nmap XML file
```

### Content item types

| Type      | Description |
|-----------|-------------|
| `text`    | Literal text with variable substitution |
| `extract` | Insert the value of a result variable (supports dot notation) |
| `nmap`    | Read and render an nmap XML output file |

### WHEN expressions

Guards on `generate_text` sub-steps accept expressions of the form:

```
<result_key>.<property> <operator> <value>
```

Supported operators: `==`, `!=`, `>`, `<`, `>=`, `<=`

```yaml
when: '$output_analyze_nmap.result == "web_only"'
when: '$output_analyze_nmap.total_open_ports > 10'
```

---

## Variable substitution

In any `command_line` or `value` field:

| Syntax            | Resolves to |
|-------------------|-------------|
| `$VAR`            | User variable (CLI or env) |
| `${VAR}`          | Same, brace form |
| `$result_key`     | Raw output of a previous step |
| `$result_key.sub` | Property inside a JSON result |
| `$SCRIPTS`        | Falls back to `./scripts` if not set |

---

## Custom output

Pass `--custom-output=my_module.py` to replace the built-in `generate_text`
rendering with your own logic.  The module must expose:

```python
def main(executor: WorkflowExecutor) -> None:
    ...
```

The executor instance gives full access to `executor.results`,
`executor.variables`, `executor.workflow`, `executor.logger`, and all
helper methods (`substitute_variables`, `evaluate_when`, etc.).

See [`custom_output/text.py`](custom_output/text.py) for a minimal example.

---

## Built-in scripts

| Script | Purpose |
|--------|---------|
| `scripts/tools/analyze_nmap.py` | Parse nmap XML/text and produce a JSON analysis |
| `scripts/web/http_headers.py` | Fetch and audit HTTP security headers |
| `scripts/web/http_methods.py` | Enumerate allowed HTTP methods |
| `scripts/web/search_error_pages.py` | Probe for common error pages |
| `scripts/variable_management/url_to_domain.py` | Strip scheme/path, return bare domain |
| `scripts/debug/debug_args.py` | Print received arguments (debug helper) |

---

## Error handling strategies

| Flag | Behaviour |
|------|-----------|
| `--error-handling stop` | *(default)* Abort immediately on any step failure |
| `--error-handling continue` | Log the error and keep running |
| `--error-handling skip` | Skip the failing step and continue |

---

## Logs

A timestamped log file is written to `logs/workflow_<timestamp>.log` on every
run.  The console shows INFO and above; the file captures DEBUG as well.

---

## Project structure

```
doer/
├── doer/
│   ├── __init__.py
│   ├── doer.py          # WorkflowExecutor + CLI
├── scripts/
│   ├── tools/           # analyze_nmap.py
│   ├── web/             # http_headers.py, http_methods.py, ...
│   ├── variable_management/
│   └── debug/
├── custom_output/
│   └── text.py          # Example custom output module
├── workflows/
│   └── network_mapping.yaml
├── pyproject.toml
└── README.md
```

---

## License

MIT — see repository for details.
