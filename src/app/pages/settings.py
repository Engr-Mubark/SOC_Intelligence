"""
Settings Page - Configuration and system health
"""

import streamlit as st


def render(analyzer):
    """Render settings page"""
    
    st.markdown("#  System Settings")
    st.markdown("Configure SOC_Intelligence platform")
    
    # System Health
    st.markdown("##  System Health")
    
    health = analyzer.health_check()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Core Services")
        st.success(f" Database: {health['database']}")
        st.info(f" LLM: {'Loaded' if health['llm']['model_loaded'] else 'Template Mode'}")
        st.write(f"**Model Path**: {health['llm'].get('model_path', 'Not configured')}")
    
    with col2:
        st.markdown("### Analysis Tools")
        zeek_status = " Enabled" if health['ingestion']['zeek'] else " Disabled"
        snort_status = " Enabled" if health['ingestion']['snort'] else " Disabled"
        
        st.write(f"**Zeek**: {zeek_status}")
        st.write(f"**Snort**: {snort_status}")
        st.success(" TTP Mapper: Ready")
        st.success(" Anomaly Detector: Ready")
    
    st.markdown("---")
    
    # Configuration
    st.markdown("##  Configuration")
    
    with st.expander("Database Settings"):
        st.text_input("DuckDB Path", value="data/soc_intelligence.duckdb", disabled=True)
        st.caption("Database location (read-only)")
    
    with st.expander("LLM Settings"):
        st.text_input("Model Path", value=health['llm'].get('model_path', 'Not configured'))
        st.selectbox("Device", ["CPU", "CUDA"], index=0)
        st.slider("Temperature", 0.0, 1.0, 0.3, 0.1)
        st.number_input("Max Tokens", value=4096, step=512)
        
        if st.button("Apply LLM Settings"):
            st.info("LLM configuration update coming in next version")
    
    with st.expander("Analysis Settings"):
        st.checkbox("Enable Zeek enrichment", value=True, disabled=not health['ingestion']['zeek'])
        st.checkbox("Enable Snort IDS", value=True, disabled=not health['ingestion']['snort'])
        st.checkbox("Enable ML Anomaly Detection", value=True)
        st.checkbox("Enable MITRE ATT&CK Mapping", value=True)
        
        if st.button("Apply Analysis Settings"):
            st.info("Analysis configuration update coming in next version")
    
    st.markdown("---")
    
    # About
    st.markdown("##  About")
    
    st.markdown("""
    **SOC_Intelligence Platform**
    
    Version: 1.0.0
    
    Unified platform combining:
    - One_Blink: Live PCAP analysis
    - SecAI Reporter: Professional SOC reports
    - Ultimate Prompt: AI-powered 14-section analysis
    
    **Features**:
    - TOON-normalized data processing (L3+ only)
    - 75/25 weighted threat analysis
    - MITRE ATT&CK technique mapping
    - ML-based anomaly detection
    - Enterprise-grade reporting (HTML/JSON/Markdown)
    
    ### System Dependencies
    
    - Python 3.10+
    - TShark (Wireshark CLI)
    - Zeek Network Monitor
    - Snort 3 IDS
    - DuckDB
    - ◈ One_Blink Dashboard
    """)
    
    st.markdown("---")
    st.caption("© 2026 SOC Intelligence Team | Ultimate Analysis Engine v1.0")
