import pandas as pd
import subprocess
import os
import tempfile
import json
import streamlit as st

def filter_by_tech(df, tech_name):
    """
    Filters the dataframe for rows where 'tech_stack' contains the tech_name.
    """
    if df.empty or 'tech_stack' not in df.columns:
        return df
    
    # tech_stack is a list of strings.
    # We apply a lambda to check if tech_name is in the list (case insensitive)
    mask = df['tech_stack'].apply(
        lambda x: any(tech_name.lower() in t.lower() for t in x) if isinstance(x, list) else False
    )
    return df[mask]

def run_nuclei(selected_subdomains):
    """
    Runs Nuclei on a list of selected subdomains.
    1. Writes targets to a temp file.
    2. Runs nuclei -l targets.txt
    3. Returns the output.
    """
    if not selected_subdomains:
        return "No targets selected."

    # Create temporary targets file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as tmp:
        for sub in selected_subdomains:
            tmp.write(f"{sub}\n")
        tmp_path = tmp.name

    try:
        # construct command
        cmd = ["nuclei", "-l", tmp_path, "-silent", "-json"]
        
        # Check if nuclei is installed
        if subprocess.call(["which", "nuclei"], stdout=subprocess.DEVNULL) != 0:
             return "❌ Nuclei binary not found in PATH."

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        
        # For this phase, we just return the raw JSON or a summary
        # In a real app we might stream this too, but for Triage button click, waiting is okay for small batches
        if process.returncode != 0:
            return f"❌ Nuclei Error:\n{stderr}"
        
        return stdout

    except Exception as e:
        return f"❌ Execution Error: {str(e)}"
    finally:
        # Cleanup
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

def generate_report(vulnerabilities):
    """
    Placeholder for more complex logic if needed before template rendering.
    """
    pass
