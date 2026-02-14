import networkx as nx
import logging
from typing import Dict, List, Set, Tuple
from modules.scanner import DLLMetadata

# Setup Logging
logger = logging.getLogger("DLLGraphBuilder")

class DependencyGraph:
    def __init__(self, metadata_store: Dict[str, DLLMetadata]):
        """
        Initialize with a dictionary of scanned DLL metadata.
        Key: lowercase filename (e.g., "kernel32.dll")
        Value: DLLMetadata object
        """
        self.metadata = metadata_store
        self.graph = nx.DiGraph()
        self.build_graph()

    def build_graph(self):
        """Constructs the NetworkX Directed Graph from metadata."""
        logger.info("Building dependency graph...")
        
        for filename, meta in self.metadata.items():
            # Add node for the DLL itself
            self.graph.add_node(filename, 
                                size=meta.size_bytes, 
                                signed=meta.is_signed,
                                path=meta.path)
            
            # Add edges for imports
            for imported_dll in meta.imports:
                imported_dll_lower = imported_dll.lower()
                
                # Add edge: "filename" DEPENDS_ON "imported_dll"
                self.graph.add_edge(filename, imported_dll_lower)
                
                # If the imported DLL wasn't scanned (e.g., System DLL not in scan path),
                # we still verify it exists in the graph as a node, but mark it as 'missing' or 'external'
                if imported_dll_lower not in self.metadata:
                    if imported_dll_lower not in self.graph.nodes:
                        self.graph.add_node(imported_dll_lower, status="missing_or_system")

        logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges.")

    def get_circular_dependencies(self) -> List[List[str]]:
        """Finds all simple cycles in the graph."""
        try:
            cycles = list(nx.simple_cycles(self.graph))
            if cycles:
                logger.warning(f"Found {len(cycles)} circular dependencies.")
            return cycles
        except Exception as e:
            logger.error(f"Error finding cycles: {e}")
            return []

    def get_orphans(self) -> List[str]:
        """
        Identifies DLLs that are NOT imported by any other DLL in the scanned set.
        Note: These might be top-level executables or unused DLLs.
        """
        orphans = [n for n, d in self.graph.in_degree() if d == 0]
        return orphans

    def get_missing_dependencies(self) -> Dict[str, List[str]]:
        """
        Returns a dictionary of {dll: [missing_imports]}.
        """
        missing = {}
        for node in self.graph.nodes:
            # We marked missing nodes with 'status' attribute in build_graph
            # But here we want to find WHO imports them.
            if self.graph.nodes[node].get("status") == "missing_or_system":
                # Find predecessors (files that import this missing dll)
                for pred in self.graph.predecessors(node):
                    if pred not in missing:
                        missing[pred] = []
                    missing[pred].append(node)
        return missing

    def export_graph_image(self, output_path: str = "dependency_graph.png"):
        """
        Attempts to draw the graph (Requires matplotlib/pygraphviz).
        """
        try:
            import matplotlib.pyplot as plt
            plt.figure(figsize=(12, 12))
            pos = nx.spring_layout(self.graph, k=0.15, iterations=20)
            nx.draw(self.graph, pos, with_labels=True, node_size=1500, node_color="skyblue", font_size=8, font_weight="bold", arrows=True)
            plt.title("DLL Dependency Graph")
            plt.savefig(output_path)
            plt.close()
            logger.info(f"Graph image saved to {output_path}")
        except ImportError:
            logger.warning("Matplotlib not installed, skipping image generation.")
        except Exception as e:
            logger.error(f"Failed to generate graph image: {e}")

if __name__ == "__main__":
    # Integration Test
    from modules.scanner import DLLScanner
    import sys
    
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print(f"Scanning {target_dir}...")
    scanner = DLLScanner()
    scanner.scan_directory(target_dir)
    
    print("Building Graph...")
    graph_builder = DependencyGraph(scanner.results)
    
    print(f"Nodes: {graph_builder.graph.number_of_nodes()}")
    print(f"Edges: {graph_builder.graph.number_of_edges()}")
    
    cycles = graph_builder.get_circular_dependencies()
    if cycles:
        print(f"Cycles found: {cycles}")
    else:
        print("No circular dependencies found.")
        
    orphans = graph_builder.get_orphans()
    print(f"Potential Orphans (Top-level binaries): {orphans[:5]}...")
