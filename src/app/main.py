"""
SOC_Intelligence - Main Streamlit Application

Unified dashboard combining:
- One_Blink: Live PCAP analysis, interactive charts
- SecAI: Professional SOC reports, historical correlation
- Ultimate: AI-powered analysis with 14-section reports
"""

import streamlit as st
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.unified.analysis.unified_analyzer import UnifiedAnalyzer
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="SOC Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #2c3e50;
        text-align: center;
        padding: 1rem 0;
        border-bottom: 3px solid #3498db;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .success-box {
        background: #d4edda;
        border-left: 4px solid #28a745;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .warning-box {
        background: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .danger-box {
        background: #f8d7da;
        border-left: 4px solid #dc3545;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        font-size: 1rem;
        border-radius: 5px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

# Initialize analyzer in session state
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = UnifiedAnalyzer()
    logger.info("Unified Analyzer initialized")

# Sidebar navigation
st.sidebar.markdown("# 🛡️ SOC Intelligence")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigate",
    ["🏠 Dashboard", "📤 PCAP Analysis", "📊 Reports", "⚙️ Settings"],
    label_visibility="collapsed"
)

st.sidebar.markdown("---")
st.sidebar.markdown("### System Health")

# Health check
health = st.session_state.analyzer.health_check()
st.sidebar.success(f"✅ Database: {health['database']}")
st.sidebar.info(f"🧠 LLM: {'Ready' if health['llm']['model_loaded'] else 'Template Mode'}")
st.sidebar.info(f"🔍 Zeek: {'Enabled' if health['ingestion']['zeek'] else 'Disabled'}")
st.sidebar.info(f"🚨 Snort: {'Enabled' if health['ingestion']['snort'] else 'Disabled'}")

st.sidebar.markdown("---")
st.sidebar.caption("SOC_Intelligence v1.0 | Ultimate Analysis Engine")

# Main content area
if page == "🏠 Dashboard":
    st.markdown('<div class="main-header">🛡️ SOC Intelligence Platform</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Welcome to SOC Intelligence
    
    A unified platform combining:
    - **Live PCAP Analysis**: Real-time network traffic forensics
    - **Professional SOC Reports**: Enterprise-grade 14-section analysis
    - **AI-Powered Intelligence**: LLM-driven threat assessment
    - **Historical Correlation**: 75/25 weighted threat scoring
    """)
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>📊 Analysis Engine</h3>
            <p style="font-size: 1.5rem; font-weight: bold;">Ready</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3>🧠 AI Models</h3>
            <p style="font-size: 1.5rem; font-weight: bold;">2 Active</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3>🎯 MITRE TTPs</h3>
            <p style="font-size: 1.5rem; font-weight: bold;">10 Types</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <h3>📈 Detectors</h3>
            <p style="font-size: 1.5rem; font-weight: bold;">5 Active</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Features overview
    st.markdown("### 🚀 Platform Capabilities")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔍 Analysis Features")
        st.markdown("""
        - ✅ PCAP Ingestion (TShark + Zeek)
        - ✅ TOON Normalization (L3+ only)
        - ✅ ML Anomaly Detection
        - ✅ MITRE ATT&CK Mapping
        - ✅ Beaconing Detection
        - ✅ DNS Tunneling Detection
        - ✅ Port Scan Detection
        """)
    
    with col2:
        st.markdown("#### 📊 Reporting Features")
        st.markdown("""
        - ✅ 14-Section Enterprise Reports
        - ✅ HTML/JSON/Markdown Export
        - ✅ Historical Correlation (75/25)
        - ✅ Evidence-Based Analysis
        - ✅ Confidence Scoring
        - ✅ Executive Summaries
        - ✅ Technical Deep Dives
        """)
    
    st.markdown("---")
    st.info("👈 Use the sidebar to navigate to PCAP Analysis or view Reports")

elif page == "📤 PCAP Analysis":
    from src.app.pages import pcap_analysis
    pcap_analysis.render(st.session_state.analyzer)

elif page == "📊 Reports":
    from src.app.pages import reports
    reports.render(st.session_state.analyzer)

elif page == "⚙️ Settings":
    from src.app.pages import settings
    settings.render(st.session_state.analyzer)
