"""
Reports Page - View and manage generated reports
"""

import streamlit as st
from pathlib import Path
import json


def render(analyzer):
    """Render reports page"""
    
    st.markdown("# 📊 Analysis Reports")
    st.markdown("View and download generated SOC intelligence reports")
    
    # Check for reports
    reports_dir = Path("reports")
    if not reports_dir.exists():
        st.warning("No reports generated yet. Analyze a PCAP file to create your first report.")
        return
    
    # List all reports
    html_reports = list(reports_dir.glob("*.html"))
    json_reports = list(reports_dir.glob("*.json"))
    md_reports = list(reports_dir.glob("*.md"))
    
    all_reports = sorted(
        html_reports + json_reports + md_reports,
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    
    if not all_reports:
        st.info("No reports found. Generate one by analyzing a PCAP file.")
        return
    
    st.markdown(f"### 📁 Total Reports: {len(all_reports)}")
    
    # Filter by format
    format_filter = st.selectbox(
        "Filter by format",
        ["All", "HTML", "JSON", "Markdown"]
    )
    
    # Display reports
    for report_path in all_reports:
        ext = report_path.suffix[1:].upper()
        
        if format_filter != "All" and ext != format_filter:
            continue
        
        with st.expander(f"📄 {report_path.name} ({report_path.stat().st_size / 1024:.1f} KB)"):
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                st.write(f"**Format**: {ext}")
                st.write(f"**Created**: {Path(report_path).stat().st_mtime}")
            
            with col2:
                # Download button
                with open(report_path, 'r') as f:
                    content = f.read()
                
                st.download_button(
                    label="📥 Download",
                    data=content,
                    file_name=report_path.name,
                    mime=f"text/{ext.lower()}"
                )
            
            with col3:
                # Delete button
                if st.button("🗑️ Delete", key=f"del_{report_path.name}"):
                    report_path.unlink()
                    st.success(f"Deleted: {report_path.name}")
                    st.rerun()
            
            # Preview
            if ext == "HTML":
                st.markdown("**Preview:**")
                st.components.v1.html(content, height=400, scrolling=True)
            
            elif ext == "JSON":
                st.markdown("**Preview:**")
                try:
                    data = json.loads(content)
                    st.json(data)
                except:
                    st.code(content[:500] + "...", language="json")
            
            elif ext in ["MD", "MARKDOWN"]:
                st.markdown("**Preview:**")
                st.markdown(content[:1000] + "\n\n..." if len(content) > 1000 else content)
