import streamlit as st
import subprocess
import pandas as pd
import json
import os
import signal
import threading
import time
from queue import Queue, Empty
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

# Import helper modules
import triage_logic

# Page Config
st.set_page_config(
    page_title="Macsecurity Recon Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- CSS & Styling ---
st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    .metric-card {
        background-color: #262730;
        border: 1px solid #464b5d;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
    }
    h1 {
        font-family: 'Inter', sans-serif;
        font-weight: 700;
        background: linear-gradient(90deg, #FF4B4B, #FF914D);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .stDataFrame {
        border: 1px solid #464b5d;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ MACSECURITY RECON")
st.markdown("### Phase 1.2: Weaponization")

# --- Sidebar ---
with st.sidebar:
    st.header("Configuration")
    target_domain = st.text_input("Target Domain", "example.com")
    
    st.markdown("---")
    
    # Binary Path
    default_bin = "./bin/recon-engine"
    bin_path = os.environ.get("RECON_BIN_PATH", default_bin)
    
    if not os.path.exists(bin_path):
        st.error(f"⚠️ Binary not found: `{bin_path}`")
        st.info("Run `make build`")
        start_btn = st.button("Start Recon", disabled=True)
    else:
        st.success(f"✅ Engine Ready")
        start_btn = st.button("Start Recon", type="primary")

# --- State Management ---
if "recon_data" not in st.session_state:
    st.session_state.recon_data = []
if "vulnerabilities" not in st.session_state:
    st.session_state.vulnerabilities = []

# --- Helper Functions for Asset Tracking ---
HISTORY_FILE = "app/recon_history.json"

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return set(json.load(f))
        except:
            return set()
    return set()

def save_history(subdomains):
    # Merge with existing
    existing = load_history()
    existing.update(subdomains)
    with open(HISTORY_FILE, "w") as f:
        json.dump(list(existing), f)

# --- Workers ---
def read_output(process, data_queue):
    for line in iter(process.stdout.readline, b''):
        data_queue.put(line.decode('utf-8'))
    process.stdout.close()

# --- Main Logic ---
tab1, tab2, tab3 = st.tabs(["🔴 Live Recon", "🧪 Vuln Triage", "📄 Reports"])

# TAB 1: LIVE RECON
with tab1:
    if start_btn:
        st.session_state.recon_data = [] # Reset on new run
        st.session_state.vulnerabilities = []
        
        status_text = st.empty()
        table_placeholder = st.empty()
        metric_col1, metric_col2, metric_col3 = st.columns(3)
        
        status_text.info(f"🚀 Launching Recon Engine against **{target_domain}**...")
        
        try:
            # Check binaries first (Go engine does this too, but good UX to fail fast)
            # Actually, Go engine handles it better with JSON error, let's trust Go.
            
            process = subprocess.Popen(
                [bin_path, target_domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=False
            )
            
            q = Queue()
            t = threading.Thread(target=read_output, args=(process, q))
            t.daemon = True
            t.start()
            
            while process.poll() is None or not q.empty():
                try:
                    line = q.get_nowait()
                    if line:
                        try:
                            data = json.loads(line)
                            # Handle Error Message from Go
                            if 'error' in data:
                                status_text.error(f"❌ {data['error']}: {data.get('message', '')}")
                                break
                                
                            st.session_state.recon_data.append(data)
                        except json.JSONDecodeError:
                            pass 
                except Empty:
                    time.sleep(0.1)
                
                if st.session_state.recon_data:
                    df = pd.DataFrame(st.session_state.recon_data)
                    metric_col1.metric("Subdomains", len(df))
                    metric_col2.metric("Live (200 OK)", len(df[df['status_code'] == 200]))
                    
                    # Display Data
                    # Highlight New Assets
                    # We can't easily do row-based styling in st.dataframe for streamed data efficiently without reloading history constantly.
                    # Instead, let's mark them in the data.
                    # For live stream, we might just show basic data.
                    # Once finished, we do the diff.
                    
                    cols_to_show = ['timestamp', 'subdomain', 'status_code', 'title', 'tech_stack']
                    # Ensure columns exist
                    disp_cols = [c for c in cols_to_show if c in df.columns]
                    
                    table_placeholder.dataframe(
                        df[disp_cols], 
                        use_container_width=True,
                        height=400
                    )
            
            if process.returncode == 0:
                status_text.success("✅ Recon Completed!")
                
                # --- Asset Tracking & Highlighting ---
                current_subs = [x['subdomain'] for x in st.session_state.recon_data]
                historical_subs = load_history()
                new_subs = set(current_subs) - historical_subs
                
                if new_subs:
                    st.toast(f"🎉 Found {len(new_subs)} NEW subdomains!")
                
                # Update Dataframe to indicate NEW
                for item in st.session_state.recon_data:
                    item['is_new'] = item['subdomain'] in new_subs
                
                # Save to history
                save_history(current_subs)
                
                # Refresh Dataframe display with 'New' badge logic (simulated by column or color)
                # Streamlit dataframe formatting is limited, but we can add an icon or column.
                
            
        except Exception as e:
            status_text.error(f"❌ Error: {str(e)}")
            
    else:
        if st.session_state.recon_data:
            df = pd.DataFrame(st.session_state.recon_data)
            
            # Add 'is_new' if not present (from history check above)
            if 'is_new' not in df.columns:
                 # Attempt load if recon was done previously but session state lost 'is_new' logic?
                 # Or just default False
                 df['is_new'] = False
            
            st.dataframe(
                df, 
                column_config={
                    "is_new": st.column_config.CheckboxColumn("New Asset?", disabled=True)
                },
                use_container_width=True
            )
        else:
            st.info("Awaiting command...")

# TAB 2: VULN TRIAGE
with tab2:
    st.header("Vulnerability Triage")
    
    if not st.session_state.recon_data:
        st.warning("No recon data available. Run 'Live Recon' first.")
    else:
        df = pd.DataFrame(st.session_state.recon_data)
        
        # 1. Tech Stack Filter
        all_techs = set()
        for stack in df['tech_stack']:
            if isinstance(stack, list):
                for t in stack:
                    all_techs.add(t)
        
        selected_tech = st.selectbox("Filter by Technology", ["All"] + list(all_techs))
        
        if selected_tech != "All":
            filtered_df = triage_logic.filter_by_tech(df, selected_tech)
        else:
            filtered_df = df.copy()

        # --- Schema Validation Test ---
        with st.expander("🛠️ Schema Debug Info"):
            if not filtered_df.empty:
                sample_tech = filtered_df.iloc[0]['tech_stack']
                st.write(f"Sample 'tech_stack' value: `{sample_tech}`")
                st.write(f"Type: `{type(sample_tech)}`")
                if isinstance(sample_tech, list):
                    st.success("✅ Schema Integrity: 'tech_stack' is a list")
                else:
                    st.error(f"❌ Schema Validation Failed: Expected list, got {type(sample_tech)}")
        
        st.subheader(f"Targets ({len(filtered_df)})")
        
        # Add Select Column
        if 'Select' not in filtered_df.columns:
            filtered_df.insert(0, "Select", False)
        
        # Add False Positive Column
        if 'False Positive' not in filtered_df.columns:
            filtered_df['False Positive'] = False

        # Risk Flagging Logic
        # We can calculate a 'Risk Score' or just a flag column to sort by.
        # High Value: File Upload, GraphQL, Auth
        sensitive_keywords = ['upload', 'graphql', 'auth', 'login', 'admin', 'api']
        
        def calculate_risk(tech_list):
            if not isinstance(tech_list, list): return False
            for t in tech_list:
                for k in sensitive_keywords:
                    if k.lower() in t.lower():
                        return True
            return False

        filtered_df['High Value'] = filtered_df['tech_stack'].apply(calculate_risk)

        # Use Data Editor for selection and False Positive marking
        edited_df = st.data_editor(
            filtered_df,
            key="triage_editor",
            column_config={
                "Select": st.column_config.CheckboxColumn(
                    "Select",
                    help="Select target for Nuclei scan",
                    default=False,
                ),
                "False Positive": st.column_config.CheckboxColumn(
                    "False Positive",
                    help="Exclude from reports",
                    default=False,
                ),
                "High Value": st.column_config.CheckboxColumn(
                    "High Value",
                    disabled=True
                )
            },
            disabled=["subdomain", "status_code", "title", "tech_stack", "High Value"],
            hide_index=True,
            use_container_width=True
        )
        
        # Persist FPs
        if not edited_df.empty and 'False Positive' in edited_df.columns:
             fps = edited_df[edited_df['False Positive'] == True]['subdomain'].tolist()
             st.session_state.fp_hosts = set(fps)
        
        # 2. Run Nuclei
        st.markdown("---")
        if st.button("☢️ Run Nuclei on Filtered Targets"):
            # Filter for selected rows
            selected_rows = edited_df[edited_df['Select'] == True]
            
            if selected_rows.empty:
                st.warning("⚠️ Please select at least one target from the list above.")
            else:
                with st.spinner(f"Running Nuclei on {len(selected_rows)} targets..."):
                    targets = selected_rows['subdomain'].tolist()
                    output = triage_logic.run_nuclei(targets)
                
                # Check for error string
                if isinstance(output, str) and output.startswith("❌"):
                    st.error(output)
                else:
                    st.success("Nuclei Scan Complete!")
                    # Try to parse Nuclei JSON output
                    # Nuclei JSON output is one JSON object per line
                    try:
                        raw_lines = output.strip().split('\n')
                        for l in raw_lines:
                            if not l: continue
                            v = json.loads(l)
                            # Minimal mapping to our schema
                            tags = v.get('info', {}).get('tags', [])
                            vuln_obj = {
                                "template": v.get('info', {}).get('name', 'Unknown'),
                                "template_id": v.get('template-id'),
                                "severity": v.get('info', {}).get('severity', 'info'),
                                "host": v.get('host'),
                                "matched_at": v.get('matched-at', ''),
                                "timestamp": v.get('timestamp'),
                                "category": triage_logic.map_tags_to_category(tags),
                                "remediation": v.get('info', {}).get('remediation', 'No specific remediation provided.')
                            }
                            st.session_state.vulnerabilities.append(vuln_obj)
                            
                        # Display raw output in expander
                        with st.expander("Raw Nuclei Output"):
                            st.text(output)
                            
                    except Exception as e:
                        st.warning(f"Could not parse Nuclei output fully: {e}")
                        st.text(output)

# TAB 3: REPORT BOT
with tab3:
    st.header("Report Generator")
    
    if st.button("Generate Report"):
        # Filter out False Positives if tracked
        fp_hosts = st.session_state.get('fp_hosts', set())
        
        # Filter vulnerabilities where host is NOT in fp_hosts
        valid_vulns = [v for v in st.session_state.vulnerabilities if v.get('host') not in fp_hosts]

        if not valid_vulns:
            st.warning("No vulnerabilities found to report (or all marked as False Positive).")
        else:
            try:
                env = Environment(loader=FileSystemLoader("app/templates"))
                template = env.get_template("report_template.md.j2")
                
                report_md = template.render(
                    target=target_domain,
                    date=datetime.now().strftime("%Y-%m-%d"),
                    vulns=valid_vulns
                )
                
                st.markdown("### Preview")
                st.markdown(report_md)
                
                st.download_button(
                    label="Download Report",
                    data=report_md,
                    file_name=f"report_{target_domain}.md",
                    mime="text/markdown"
                )
            except Exception as e:
                st.error(f"Template Error: {e}")

