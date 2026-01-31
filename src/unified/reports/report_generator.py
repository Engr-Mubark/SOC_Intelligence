"""
Report Generator for SOC_Intelligence

Generates professional 14-section enterprise reports following Ultimate Prompt spec.
Supports HTML, JSON, and Markdown output formats.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import json

from unified.models.schemas import AnalysisReport, TOONEvent, WeightedThreatScore, TTP
from unified.ai.llm_service import LocalLLMService
from unified.analysis.ttp_mapper import TTPMapper
from unified.analysis.anomaly_detector import AnomalyDetector
from unified.db.duckdb_adapter import DuckDBAdapter

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Enterprise-grade SOC report generation
    
    Features:
    - 14-section structure (Ultimate Prompt)
    - 75/25 weighted threat analysis
    - MITRE ATT&CK mapping
    - Multiple output formats
    """
    
    def __init__(
        self,
        llm: LocalLLMService,
        ttp_mapper: TTPMapper,
        anomaly_detector: AnomalyDetector,
        db: DuckDBAdapter
    ):
        self.llm = llm
        self.ttp_mapper = ttp_mapper
        self.anomaly_detector = anomaly_detector
        self.db = db
    
    def generate_report(
        self,
        events: List[TOONEvent],
        ticket_context: Optional[Dict] = None,
        output_format: str = "markdown"
    ) -> str:
        """
        Generate complete analysis report
        
        Args:
            events: TOON normalized events
            ticket_context: Optional ticket metadata
            output_format: "markdown", "html", or "json"
        
        Returns:
            Generated report in requested format
        """
        
        logger.info(f"Generating {output_format} report for {len(events)} events")
        
        # Step 1: Get historical stats (for 75/25 weighting)
        historical_stats = None
        if ticket_context and ticket_context.get('ioc_value'):
            historical_stats = self.db.get_historical_stats(ticket_context['ioc_value'])
            logger.info(f"Historical stats: {historical_stats}")
        
        # Step 2: Detect TTPs
        ttps = self.ttp_mapper.infer_techniques(events)
        logger.info(f"Detected {len(ttps)} TTPs")
        
        # Step 3: Detect anomalies
        anomalies = self.anomaly_detector.detect_anomalies(events)
        logger.info(f"Detected {anomalies['total_anomalies']} anomalies")
        
        # Step 4: Generate with LLM
        report_md = self.llm.generate_analysis(
            toon_events=events,
            ticket_context=ticket_context,
            historical_stats=historical_stats,
            detected_ttps=ttps
        )
        
        # Step 5: Format output
        if output_format == "markdown":
            return report_md
        elif output_format == "html":
            return self._convert_to_html(report_md, events, ttps, anomalies)
        elif output_format == "json":
            return self._convert_to_json(report_md, events, ttps, anomalies, historical_stats)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def _convert_to_html(
        self,
        report_md: str,
        events: List[TOONEvent],
        ttps: List[TTP],
        anomalies: Dict
    ) -> str:
        """Convert markdown report to HTML"""
        
        # Simple markdown-to-HTML conversion
        import markdown
        
        html_body = markdown.markdown(
            report_md,
            extensions=['tables', 'fenced_code', 'nl2br']
        )
        
        # Wrap in professional HTML template
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Intelligence Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        h3 {{
            color: #555;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        table th, table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        table th {{
            background: #3498db;
            color: white;
        }}
        table tr:nth-child(even) {{
            background: #f9f9f9;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .verdict-malicious {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .verdict-suspicious {{
            color: #f39c12;
            font-weight: bold;
        }}
        .verdict-benign {{
            color: #27ae60;
            font-weight: bold;
        }}
        .confidence-high {{
            color: #27ae60;
        }}
        .confidence-medium {{
            color: #f39c12;
        }}
        .confidence-low {{
            color: #e74c3c;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html_body}
        
        <div class="footer">
            <p>Generated by SOC_Intelligence Ultimate Analysis Engine v1.0</p>
            <p>Timestamp: {datetime.now().isoformat()}</p>
            <p>Total Events Analyzed: {len(events)}</p>
            <p>TTPs Detected: {len(ttps)}</p>
            <p>Anomalies Found: {anomalies.get('total_anomalies', 0)}</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _convert_to_json(
        self,
        report_md: str,
        events: List[TOONEvent],
        ttps: List[TTP],
        anomalies: Dict,
        historical_stats: Optional[Dict]
    ) -> str:
        """Convert report to JSON (for SIEM/SOAR integration)"""
        
        output = {
            "report_id": f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "analyst_engine": "SOC_Intelligence Ultimate v1.0",
            "markdown_report": report_md,
            "summary": {
                "total_events": len(events),
                "ttps_detected": len(ttps),
                "anomalies_found": anomalies.get('total_anomalies', 0)
            },
            "ttps": [
                {
                    "technique_id": ttp.technique_id,
                    "technique_name": ttp.technique_name,
                    "tactic": ttp.tactic,
                    "confidence": ttp.confidence,
                    "evidence": ttp.evidence
                }
                for ttp in ttps
            ],
            "anomalies": anomalies,
            "historical_stats": historical_stats,
            "events_sample": [
                {
                    "timestamp": e.t,
                    "src": e.si,
                    "dst": e.di,
                    "protocol": e.pr,
                    "details": {
                        "dns_query": e.dns_query,
                        "http_host": e.http_host,
                        "tls_sni": e.tls_sni
                    }
                }
                for e in events[:20]  # First 20 events
            ]
        }
        
        return json.dumps(output, indent=2)
    
    def save_report(
        self,
        report_content: str,
        output_path: Path,
        format: str = "html"
    ) -> Path:
        """
        Save report to file
        
        Args:
            report_content: Generated report string
            output_path: Where to save
            format: File format
        
        Returns:
            Path to saved report
        """
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"Report saved: {output_path}")
        return output_path
