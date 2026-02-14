# DLL Intelligence Engine - API Reference

## Core Modules

### 1. Scanner (`modules.scanner`)

#### `class DLLScanner`

The primary entry point for static file analysis.

* `scan_directory(directory: str, recursive: bool = True) -> Dict[str, DLLMetadata]`
  * Recursively walks the target directory.
  * Returns a dictionary mapping filenames to `DLLMetadata` objects.
  * **Performance**: Uses `ThreadPoolExecutor` for parallel processing.

#### `dataclass DLLMetadata`

* `path`: Absolute path to the file.
* `size_bytes`: File size.
* `md5`, `sha256`: Cryptographic hashes.
* `imports`: List of imported DLL names (from PE Import Table).
* `is_signed`: Boolean indicating if Authenticode signature is present.
* `entropy`: Float (0-8) indicating information density (High > 7.0 suggests packing).

### 2. Graph Builder (`modules.graph_builder`)

#### `class DependencyGraph`

Constructs and analyzes the dependency network.

* `__init__(metadata_store: Dict[str, DLLMetadata])`
  * Initializes the graph from scan results.
* `get_circular_dependencies() -> List[List[str]]`
  * Detects cycles (e.g., A -> B -> A), which can cause load-order issues.
* `get_orphans() -> List[str]`
  * Returns list of DLLs that no other scanned DLL depends on.

### 3. Usage Analyzer (`modules.runtime_analyzer`)

#### `class RuntimeAnalyzer`

Interacts with the Windows Kernel to inspect running processes.

* `scan_running_processes()`
  * Snapshots all accessible processes and their loaded modules.
  * **Note**: Requires Admin privileges for full system visibility.
* `get_users_of_dll(dll_name: str) -> List[Tuple[int, str]]`
  * Returns `[(PID, ProcessName), ...]` for a given DLL.

### 4. Impact Engine (`modules.impact`)

#### `class ImpactSimulator`

Calculates risk scores based on graph topology and runtime state.

* `simulate_removal(dll_name: str) -> Dict`
  * Returns a detailed impact report:

        ```json
        {
          "risk_score": 150,
          "risk_level": "CRITICAL",
          "reason": ["System Critical", "Used by 5 processes"],
          ...
        }
        ```

## Development Guide

### Running Tests

(Placeholder for unittest command)
`python -m unittest discover tests`

### Adding a New Module

1. Create `modules/new_module.py`
2. Implement your logic class.
3. Import it in `main.py` and `dashboard.py`.
