import logging
from typing import Dict, List, Set
from modules.graph_builder import DependencyGraph
from modules.runtime_analyzer import RuntimeAnalyzer

# Setup Logging
logger = logging.getLogger("ImpactEngine")

class ImpactSimulator:
    def __init__(self, graph_builder: DependencyGraph, runtime_analyzer: RuntimeAnalyzer):
        self.graph = graph_builder.graph
        self.runtime = runtime_analyzer

    def simulate_removal(self, dll_name: str) -> Dict[str, any]:
        """
        Simulate the impact of removing a specific DLL.
        Returns a dictionary containing impact assessment.
        """
        dll_name = dll_name.lower()
        impact = {
            "target": dll_name,
            "risk_score": 0,
            "risk_level": "LOW",
            "broken_dependencies": [],
            "affected_processes": [],
            "is_system_critical": False,
            "reason": []
        }

        # Check existence in graph
        if dll_name not in self.graph.nodes:
            impact["reason"].append("DLL not found in dependency graph.")
            return impact

        # 1. Identify Dependent DLLs (Static Dependencies)
        # Find all nodes that have an edge pointing TO target
        dependents = list(self.graph.predecessors(dll_name))
        impact["broken_dependencies"] = dependents
        
        # 2. Identify Running Processes (Runtime Usage)
        # Note: Runtime Analyzer maps full paths or normalized paths. 
        # We need to check if any of the loaded DLLs match our target filename.
        users = self.runtime.get_users_of_dll(dll_name)
        impact["affected_processes"] = [f"{name} ({pid})" for pid, name in users]

        # 3. Check System Criticality
        # Naive check: if in System32 (requires full path in node data)
        node_data = self.graph.nodes[dll_name]
        full_path = node_data.get("path", "").lower()
        if "system32" in full_path or "syswow64" in full_path:
            impact["is_system_critical"] = True

        # 4. Calculate Risk Score
        score = 0
        reasons = []

        if impact["is_system_critical"]:
            score += 100
            reasons.append("Critical System File")
        
        if len(impact["affected_processes"]) > 0:
            score += 50
            reasons.append(f"Used by {len(users)} active processes")
        
        num_deps = len(dependents)
        if num_deps > 0:
            score += (num_deps * 10)
            reasons.append(f"Required by {num_deps} other libraries")

        impact["risk_score"] = score
        impact["reason"].extend(reasons)

        # 5. Determine Risk Level
        if score >= 90:
            impact["risk_level"] = "CRITICAL"
        elif score >= 50:
            impact["risk_level"] = "HIGH"
        elif score >= 20:
            impact["risk_level"] = "MEDIUM"
        else:
            impact["risk_level"] = "LOW"

        return impact

if __name__ == "__main__":
    # Integration Test Placeholder
    # Needs a mock graph and runtime state to run
    pass
