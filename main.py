import typer
import sys
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import Optional

from modules.scanner import DLLScanner
from modules.graph_builder import DependencyGraph
from modules.runtime_analyzer import RuntimeAnalyzer
from modules.security import SecurityAnalyzer
from modules.impact import ImpactSimulator
from modules.safe_removal import backup_manager

# Setup Application
app = typer.Typer(help="DLL Intelligence Engine - CLI")
console = Console()
logging.basicConfig(level=logging.ERROR) # Suppress info logs in CLI mode unless verbose

# Global State (In a real app, use a proper context or database)
scanner = DLLScanner()
graph_builder = None 

@app.command()
def scan(directory: str = ".", recursive: bool = True):
    """
    Scan a directory for DLLs and build the intelligence database.
    """
    console.print(f"[bold green]Scanning directory:[/bold green] {directory}")
    
    with console.status("[bold green]Scanning files...[/bold green]"):
        results = scanner.scan_directory(directory, recursive)
    
    console.print(f"[bold blue]Found {len(results)} binaries.[/bold blue]")
    
    # Build Graph
    global graph_builder
    graph_builder = DependencyGraph(results)
    
    # Display Summary Table
    table = Table(title="Scan Results")
    table.add_column("Filename", style="cyan")
    table.add_column("Size (KB)", justify="right")
    table.add_column("Signed", justify="center")
    table.add_column("Entropy", justify="right")
    
    for name, meta in list(results.items())[:10]: # Show top 10
        signed_mark = "✅" if meta.is_signed else "❌"
        entropy_style = "red" if meta.entropy > 7.0 else "green"
        table.add_row(
            meta.filename,
            f"{meta.size_bytes / 1024:.2f}",
            signed_mark,
            f"[{entropy_style}]{meta.entropy:.2f}[/{entropy_style}]"
        )
    
    console.print(table)
    if len(results) > 10:
        console.print(f"... and {len(results) - 10} more.")

@app.command()
def analyze_security():
    """
    Analyze scanned DLLs for security risks (Entropy, Unsigned, Duplicates).
    """
    if not scanner.results:
        console.print("[bold red]Error:[/bold red] Please run 'scan' first.")
        return

    sec = SecurityAnalyzer(scanner.results)
    
    # Check Unsigned
    unsigned = sec.find_unsigned_dlls()
    console.print(Panel(f"[bold red]{len(unsigned)} Unsigned DLLs found[/bold red]", title="Security Audit"))
    
    # Check High Entropy
    high_entropy = sec.find_high_entropy_files()
    if high_entropy:
        console.print("\n[bold yellow]Suspicious High Entropy Files (Packed/Encrypted):[/bold yellow]")
        for name, ent in high_entropy[:5]:
             console.print(f" - {name}: {ent:.2f}")

    # Check Duplicates
    duplicates = sec.find_duplicates()
    if duplicates:
        console.print(f"\n[bold blue]Found {len(duplicates)} Duplicate Groups (Redundancy):[/bold blue]")
        for hash_val, files in list(duplicates.items())[:3]:
            console.print(f" - Hash {hash_val[:8]}...: {len(files)} copies")
            for f in files:
                console.print(f"   -> {f}")

@app.command()
def check_impact(dll_name: str):
    """
    Simulate the impact of removing a specific DLL.
    """
    if not scanner.results:
        console.print("[bold red]Error:[/bold red] Please run 'scan' first.")
        return
        
    global graph_builder
    if not graph_builder:
        graph_builder = DependencyGraph(scanner.results)

    # Scrape runtime
    runtime = RuntimeAnalyzer()
    with console.status("Snapshotting runtime state..."):
        runtime.scan_running_processes()

    simulator = ImpactSimulator(graph_builder, runtime)
    impact = simulator.simulate_removal(dll_name)

    # Render Report
    risk_color = "green"
    if impact["risk_level"] == "HIGH": risk_color = "orange3"
    if impact["risk_level"] == "CRITICAL": risk_color = "red"

    msg = Text()
    msg.append(f"Target: {impact['target']}\n", style="bold")
    msg.append(f"Risk Level: {impact['risk_level']}\n", style=f"bold {risk_color}")
    msg.append(f"Risk Score: {impact['risk_score']}\n")
    
    panel = Panel(msg, title="Impact Analysis", border_style=risk_color)
    console.print(panel)

    if impact["is_system_critical"]:
         console.print("[bold red]!!! SYSTEM CRITICAL FILE DETECTED !!![/bold red]")

    if impact["affected_processes"]:
        console.print("\n[bold red]Active Processes Using This DLL:[/bold red]")
        for p in impact["affected_processes"]:
            console.print(f" - {p}")
            
    if impact["broken_dependencies"]:
        console.print(f"\n[bold yellow]Broken Dependencies ({len(impact['broken_dependencies'])}):[/bold yellow]")
        for dep in impact["broken_dependencies"][:10]:
            console.print(f" - {dep}")

@app.command()
def runtime_audit():
    """
    Audit currently running processes for loaded DLLs.
    """
    analyzer = RuntimeAnalyzer()
    with console.status("Scanning processes..."):
        analyzer.scan_running_processes()
        
    table = Table(title="Top Loaded DLLs")
    table.add_column("DLL Path", style="cyan")
    table.add_column("Usage Count", justify="right")
    
    # Sort by usage
    # Need to flip the dict loaded_dlls: {path: [pids]} -> sorting by len(pids)
    sorted_dlls = sorted(analyzer.loaded_dlls.items(), key=lambda x: len(x[1]), reverse=True)
    
    for path, pids in sorted_dlls[:15]:
        table.add_row(os.path.basename(path), str(len(pids)))
        
    console.print(table)

if __name__ == "__main__":
    app()
