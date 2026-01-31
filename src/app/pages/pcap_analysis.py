"""
PCAP Analysis Page - Interactive Upload and Analysis
"""

import streamlit as st
from pathlib import Path
import time
from datetime import datetime


def render(analyzer):
    """Render PCAP analysis page"""
    
    st.markdown("# 📤 PCAP Analysis")
    st.markdown("Upload a PCAP file for comprehensive network forensics analysis")
    
    # File uploader
    uploaded_file = st.file_uploader(
        "Upload PCAP File",
        type=['pcap', 'pcapng'],
        help="Support for PCAP and PCAPNG formats"
    )
    
    if uploaded_file is not None:
        # Save uploaded file
        upload_dir = Path("uploads")
        upload_dir.mkdir(exist_ok=True)
        
        pcap_path = upload_dir / uploaded_file.name
        with open(pcap_path, 'wb') as f:
            f.write(uploaded_file.getvalue())
        
        st.success(f"✅ File uploaded: {uploaded_file.name} ({uploaded_file.size / 1024:.2f} KB)")
        
        # Analysis options
        st.markdown("### Analysis Options")
        
        col1, col2 = st.columns(2)
        
        with col1:
            create_ticket = st.checkbox("Create SOC Ticket", value=True)
            enable_zeek = st.checkbox("Zeek Enrichment", value=True, disabled=not analyzer.ingestion.zeek_enabled)
        
        with col2:
            enable_snort = st.checkbox("Snort IDS", value=True, disabled=not analyzer.ingestion.snort_enabled)
            output_format = st.selectbox("Report Format", ["html", "json", "markdown"])
        
        # Analyze button
        if st.button("🚀 Start Analysis", type="primary"):
            analyze_pcap(analyzer, pcap_path, create_ticket, output_format)


def analyze_pcap(analyzer, pcap_path, create_ticket, output_format):
    """Run PCAP analysis with progress tracking"""
    
    # Progress container
    progress_container = st.container()
    
    with progress_container:
        st.markdown("### 🔄 Analysis in Progress...")
        
        # Progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Phase 1: Ingestion
        status_text.text("Phase 1/4: PCAP Ingestion (TShark extraction)...")
        progress_bar.progress(10)
        
        start_time = time.time()
        
        try:
            # Run analysis
            result = analyzer.analyze_pcap(
                pcap_path=pcap_path,
                create_ticket=create_ticket,
                output_format=output_format
            )
            
            # Update progress
            status_text.text("Phase 2/4: TTP Mapping & Anomaly Detection...")
            progress_bar.progress(40)
            time.sleep(0.5)
            
            status_text.text("Phase 3/4: AI Analysis (Ultimate Prompt)...")
            progress_bar.progress(70)
            time.sleep(0.5)
            
            status_text.text("Phase 4/4: Report Generation...")
            progress_bar.progress(95)
            time.sleep(0.5)
            
            progress_bar.progress(100)
            status_text.text("✅ Analysis Complete!")
            
            elapsed = time.time() - start_time
            
            # Display results
            st.markdown("---")
            st.markdown("## 📊 Analysis Results")
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Events Analyzed", f"{result['events_count']:,}")
            
            with col2:
                st.metric("TTPs Detected", len(result['ttps']))
            
            with col3:
                st.metric("Anomalies Found", result['anomalies']['total_anomalies'])
            
            with col4:
                st.metric("Processing Time", f"{elapsed:.1f}s")
            
            # TTPs
            if result['ttps']:
                st.markdown("### 🎯 MITRE ATT&CK Techniques")
                
                for ttp in result['ttps']:
                    with st.expander(f"**{ttp['id']}**: {ttp['name']} ({ttp['tactic']})"):
                        st.write(f"**Confidence**: {ttp['confidence']}")
            
            # Anomalies
            st.markdown("### ⚠️ Detected Anomalies")
            
            anom_col1, anom_col2 = st.columns(2)
            
            with anom_col1:
                if result['anomalies']['beaconing']:
                    st.markdown("**🔔 Beaconing Detected**")
                    for beacon in result['anomalies']['beaconing'][:3]:
                        st.code(f"{beacon['src']} → {beacon['dst']}:{beacon['port']} "
                               f"({beacon['interval_avg']}s intervals, {beacon['beacons_count']} beacons)")
                
                if result['anomalies']['port_scans']:
                    st.markdown("**🔍 Port Scans Detected**")
                    for scan in result['anomalies']['port_scans'][:3]:
                        st.code(f"{scan['src']}: {scan['unique_ports']} ports scanned")
            
            with anom_col2:
                if result['anomalies']['dns_tunneling']:
                    st.markdown("**🌐 DNS Tunneling Suspected**")
                    for tunnel in result['anomalies']['dns_tunneling'][:3]:
                        st.code(f"Query: {tunnel.get('query', 'N/A')[:50]}...")
            
            # Report
            st.markdown("### 📄 Generated Report")
            st.info(f"📁 Report saved: `{result['report_path']}`")
            
            # Download button
            report_path = Path(result['report_path'])
            if report_path.exists():
                with open(report_path, 'r') as f:
                    report_content = f.read()
                
                st.download_button(
                    label=f"📥 Download {output_format.upper()} Report",
                    data=report_content,
                    file_name=report_path.name,
                    mime=f"text/{output_format}"
                )
            
            # Ticket info
            if result.get('ticket_id'):
                st.success(f"🎫 Ticket created: **{result['ticket_id']}**")
            
        except Exception as e:
            progress_bar.progress(0)
            st.error(f"❌ Analysis failed: {str(e)}")
            st.exception(e)
