import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

from modules.scanner import DLLScanner
from modules.graph_builder import DependencyGraph
from modules.runtime_analyzer import RuntimeAnalyzer
from modules.security import SecurityAnalyzer
from modules.impact import ImpactSimulator

# --- CONFIGURATION ---
st.set_page_config(
    page_title="DLL Intelligence Engine",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- ASSETS & STYLE ---
def load_css():
    css_path = os.path.join("assets", "style.css")
    if os.path.exists(css_path):
        with open(css_path, "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    else:
        st.warning("CS not found: assets/style.css")

load_css()

# --- HELPER COMPONENTS ---
def metric_card(label, value, delta=None, status="neutral"):
    """
    Renders a custom HTML metric card.
    Status can be: neutral, success, warning, danger
    """
    # Just format delta, don't color it (handled by class)
    delta_html = f"<div class='delta'>{delta}</div>" if delta else ""
    
    html = f"""
    <div class="metric-card {status}">
        <h3>{label}</h3>
        <div class="value">{value}</div>
        {delta_html}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

# --- SESSION STATE ---
if 'scanner' not in st.session_state:
    st.session_state.scanner = DLLScanner()
if 'graph' not in st.session_state:
    st.session_state.graph = None

# --- SIDEBAR NAV ---
st.sidebar.markdown("## 🛡️ DLL ENGINE")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "NAVIGATION", 
    ["SCANNER", "DEPENDENCY GRAPH", "SECURITY AUDIT", "RUNTIME MONITOR", "IMPACT SIMULATOR"]
)
st.sidebar.markdown("---")
st.sidebar.info("v1.2.0 • Cyber-Security Edition")

# --- HEADER STATUS ---
col1, col2, col3, col4 = st.columns(4)
total_files = len(st.session_state.scanner.results) if st.session_state.scanner.results else 0
with col1:
    metric_card("Total Objects", total_files, status="neutral")
with col2:
    signed_count = sum(1 for m in st.session_state.scanner.results.values() if m.is_signed) if total_files else 0
    metric_card("Verified Signed", signed_count, status="success" if signed_count > 0 else "neutral")
with col3:
    unsigned_count = total_files - signed_count
    metric_card("Unsigned Risk", unsigned_count, status="warning" if unsigned_count > 0 else "success")
with col4:
    metric_card("System Status", "ONLINE", status="success")

st.markdown("---")

# --- PAGE: SCANNER ---
if page == "SCANNER":
    st.title("📂 FILESYSTEM SCANNER")
    st.markdown("Recursive indexing of PE binaries. Extracts metadata, signatures, and entropy.")
    
    col_input, col_btn = st.columns([3, 1])
    with col_input:
        target_dir = st.text_input("Target Directory", value=r"C:\Program Files")
    with col_btn:
        st.write("") # Spacer
        st.write("") # Spacer
        if st.button("INITIATE SCAN"):
            with st.spinner(f"SCANNING TARGET: {target_dir}..."):
                st.session_state.scanner = DLLScanner() # Reset
                results = st.session_state.scanner.scan_directory(target_dir)
                st.toast(f"SCAN COMPLETE: {len(results)} OBJECTS FOUND")
                st.rerun()

    if st.session_state.scanner.results:
        # Convert to DataFrame for display
        data = []
        for meta in st.session_state.scanner.results.values():
            data.append({
                "FILENAME": meta.filename,
                "SIZE (KB)": round(meta.size_bytes / 1024, 2),
                "SIGNED": meta.is_signed, # Bool for column config
                "ENTROPY": round(meta.entropy, 2),
                "PATH": meta.path
            })
        df = pd.DataFrame(data)
        
        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "SIGNED": st.column_config.CheckboxColumn(
                    "SIGNED",
                    help="Is the binary digitally signed?",
                    default=False,
                ),
                "ENTROPY": st.column_config.ProgressColumn(
                    "ENTROPY",
                    format="%.2f",
                    min_value=0,
                    max_value=8,
                ),
            },
            hide_index=True
        )
    else:
        st.info("Awaiting user input. Initiate a scan to populate the database.")

# --- PAGE: GRAPH ---
elif page == "DEPENDENCY GRAPH":
    st.title("🕸️ DEPENDENCY GRAPH")
    
    if not st.session_state.scanner.results:
        st.warning("DATABASE EMPTY. RUN SCAN First.")
    else:
        col_act, col_res = st.columns([1, 3])
        
        with col_act:
            if st.button("BUILD GRAPH MODEL"):
                with st.spinner("Constructing Directed Acyclic Graph..."):
                    st.session_state.graph = DependencyGraph(st.session_state.scanner.results)
                    st.success("GRAPH MODEL READY")
            
            if st.session_state.graph:
                gb = st.session_state.graph
                orphans = gb.get_orphans()
                cycles = gb.get_circular_dependencies()
                
                st.markdown("### METRICS")
                metric_card("Nodes", gb.graph.number_of_nodes())
                metric_card("Edges", gb.graph.number_of_edges())
                metric_card("Orphans", len(orphans), status="warning" if orphans else "success")
                metric_card("Cycles", len(cycles), status="danger" if cycles else "success")

        with col_res:
            if st.session_state.graph:
                st.markdown("### TOPOLOGY VISUALIZATION (PREVIEW)")
                # Simple Plotly placeholder for the graph (NetworkX is heavy to plot fully interactively)
                # In a real "Cyber" UI, we might use st-cytoscape here. 
                # For now, we listed critical nodes.
                
                tab1, tab2 = st.tabs(["ORPHANS", "CYCLES"])
                with tab1:
                    st.write(orphans)
                with tab2:
                    if cycles:
                        st.error("CIRCULAR DEPENDENCIES DETECTED")
                        st.json(cycles)
                    else:
                        st.success("NO CYCLES DETECTED")

# --- PAGE: SECURITY ---
elif page == "SECURITY AUDIT":
    st.title("🛡️ SECURITY AUDIT")
    
    if not st.session_state.scanner.results:
        st.warning("DATABASE EMPTY. RUN SCAN First.")
    else:
        sec = SecurityAnalyzer(st.session_state.scanner.results)
        
        tab1, tab2, tab3 = st.tabs(["UNSIGNED BINARIES", "HIGH ENTROPY", "DUPLICATES"])
        
        with tab1:
            unsigned = sec.find_unsigned_dlls()
            st.markdown(f"### ⚠️ DETECTED: {len(unsigned)} UNSIGNED BINARIES")
            if unsigned:
                st.dataframe(pd.DataFrame(unsigned, columns=["File Path"]), use_container_width=True)
            
        with tab2:
            high_ent = sec.find_high_entropy_files()
            st.markdown("### ⚠️ HIGH ENTROPY (> 7.0)")
            st.caption("High entropy may indicate packed code, encryption, or compressed malware payload.")
            if high_ent:
                df_ent = pd.DataFrame(high_ent, columns=["Filename", "Entropy"])
                st.dataframe(
                    df_ent, 
                    use_container_width=True,
                    column_config={
                         "Entropy": st.column_config.ProgressColumn(
                            "Entropy",
                            format="%.2f",
                            min_value=0,
                            max_value=8,
                        ),
                    }
                )
            else:
                st.success("No high entropy files detected.")
            
        with tab3:
            dupes = sec.find_duplicates()
            st.markdown(f"### ♻️ DUPLICATE GROUPS: {len(dupes)}")
            for h, files in list(dupes.items())[:10]:
                with st.expander(f"HASH: {h[:8]}... ({len(files)} COPIES)"):
                    for f in files:
                        st.code(f, language="bash")

# --- PAGE: RUNTIME ---
elif page == "RUNTIME MONITOR":
    st.title("⚡ RUNTIME KERNEL MONITOR")
    
    if st.button("SNAPSHOT SYSTEM PROCESSES"):
        with st.spinner("ACCESSING MEMORY MAPS..."):
            runtime = RuntimeAnalyzer()
            runtime.scan_running_processes()
            
            # DataFrame
            data = []
            for path, pids in runtime.loaded_dlls.items():
                data.append({
                    "MODULE": os.path.basename(path),
                    "PATH": path,
                    "PROCESS_COUNT": len(pids),
                    "PIDS": str(pids[:5]) + ("..." if len(pids)>5 else "")
                })
            df = pd.DataFrame(data).sort_values("PROCESS_COUNT", ascending=False)
            
            # Interactive Chart
            fig = px.bar(
                df.head(20), 
                x="PROCESS_COUNT", 
                y="MODULE", 
                orientation='h',
                template="plotly_dark",
                color="PROCESS_COUNT",
                title="TOP 20 LOADED MODULES",
                color_continuous_scale=["#00E5FF", "#D946EF"]
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("### RAW DATA")
            st.dataframe(df, use_container_width=True, hide_index=True)

# --- PAGE: IMPACT ---
elif page == "IMPACT SIMULATOR":
    st.title("⚠️ IMPACT SIMULATOR")
    st.markdown("Predictive analysis of removal consequences.")
    
    target_dll = st.text_input("TARGET DLL FILENAME (e.g. kernel32.dll)")
    
    if st.button("RUN SIMULATION"):
        if not st.session_state.scanner.results:
            st.error("ERROR: STATIC SCAN REQUIRED")
        elif not target_dll:
            st.error("ERROR: TARGET REQUIRED")
        else:
            # Build ephemeral graph/runtime if needed
            if not st.session_state.graph:
                 st.session_state.graph = DependencyGraph(st.session_state.scanner.results)
            
            with st.spinner("CALCULATING RISK VECTORS..."):
                runtime = RuntimeAnalyzer()
                runtime.scan_running_processes()
                
                sim = ImpactSimulator(st.session_state.graph, runtime)
                impact = sim.simulate_removal(target_dll)
                
                # Display Score
                level = impact['risk_level']
                status = "success"
                if level == "HIGH": status = "warning"
                if level == "CRITICAL": status = "danger"
                
                col_score, col_details = st.columns([1, 2])
                with col_score:
                    metric_card("RISK SCORE", impact['risk_score'], status=status)
                    metric_card("RISK LEVEL", level, status=status)
                
                with col_details:
                    st.markdown("### IMPACT REPORT")
                    for r in impact['reason']:
                        st.markdown(f"- {r}")
                    
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### 🧱 BROKEN DEPENDENCIES")
                    st.dataframe(pd.DataFrame(impact['broken_dependencies'], columns=["Dependent File"]), use_container_width=True)
                with col2:
                     st.markdown("### ⚙️ AFFECTED PROCESSES")
                     st.dataframe(pd.DataFrame(impact['affected_processes'], columns=["Process Name"]), use_container_width=True)
