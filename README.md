# DLL Intelligence Engine

A professional-grade system analysis tool designed to illuminate the complex web of Dynamic Link Libraries (DLLs) on Windows systems. This engine provides deep visibility into dependencies, security risks, runtime usage, and the potential impact of modifications.

## Core Features

- **🔍 Deep Scanning**: Recursively indexes DLLs, extracting PE metadata, Authenticode signatures, and cryptographic hashes.
- **🕸️ Dependency Graphing**: Builds a directed graph of system dependencies to visualize relationships and detect circular references.
- **🛡️ Security Audit**: identifies unsigned binaries, high-entropy files (potential malware/packing), and redundant duplicates.
- **⚡ Runtime Analysis**: Monitors active processes to correlate disk files with loaded modules in real-time.
- **⚠️ Impact Simulation**: "What-If" engine that calculates the risk of removing a DLL by analyzing its dependents and current usage.
- **💾 Safe Operations**: Integrated backup and restore mechanisms to prevent accidental system damage.

## Installation

Requires Python 3.10+ and Windows.

```bash
# Clone the repository
git clone <repo-url>
cd DLL_Engine

# Install dependencies
pip install -r requirements.txt
# (Dependencies: typer, rich, networkx, pefile, psutil, pywin32)
```

## Usage

The system is controlled via a rich CLI.

### 1. Scan a Directory

Build the intelligence database by scanning a target directory.

```bash
python main.py scan "C:\Program Files\MyApp"
```

### 2. Security Audit

Analyze the scanned files for vulnerabilities and inefficiencies.

```bash
python main.py analyze-security
```

### 3. Impact Analysis

Simulate the removal of a specific DLL to see what breaks.

```bash
python main.py check-impact kernel32.dll
```

### 4. Runtime Audit

See what DLLs are currently loaded by active processes.

```bash
python main.py runtime-audit
```

### 5. Interactive Dashboard 📊 (New)

Launch the visual web interface for easier analysis.

```bash
streamlit run dashboard.py
```

## Architecture

The system uses a **Modular Monolith** design:

- **Scanner**: `pefile` based static analysis.
- **Graph**: `networkx` based dependency tracking.
- **Runtime**: `psutil` based memory mapping.
- **Impact**: Heuristic risk calculation engine.
- **Dashboard**: `streamlit` + `plotly` for visualization.

## License

Proprietary / Enterprise License.
