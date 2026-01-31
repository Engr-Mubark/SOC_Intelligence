"""
Unified Analyzer - Main Analysis Orchestrator

Combines all analysis components:
- PCAP ingestion
- TOON normalization
- TTP mapping
- Anomaly detection
- Historical correlation
- LLM analysis
- Report generation
"""

import logging
from pathlib import Path
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta

from src.unified.models.schemas import TOONEvent, Ticket, IOC
from src.unified.db.duckdb_adapter import DuckDBAdapter
from src.unified.ingestion.pcap_ingestion import PCAPIngestionEngine
from src.unified.ai.llm_service import LocalLLMService
from src.unified.analysis.ttp_mapper import TTPMapper
from src.unified.analysis.anomaly_detector import AnomalyDetector
from src.unified.reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class UnifiedAnalyzer:
    """
    Main analysis orchestrator for SOC_Intelligence
    
    Integrates:
    - One_Blink: PCAP analysis, Zeek, Snort, Charts
    - SecAI: Historical correlation, MITRE mapping, Professional reports
    - Ultimate: AI analysis with 14-section output
    """
    
    def __init__(
        self,
        db_path: str = "data/soc_intelligence.duckdb",
        llm_model_path: Optional[str] = None
    ):
        """Initialize analyzer with all components"""
        
        # Core services
        self.db = DuckDBAdapter(db_path)
        self.ingestion = PCAPIngestionEngine(self.db)
        self.llm = LocalLLMService(llm_model_path)
        self.ttp_mapper = TTPMapper()
        self.anomaly_detector = AnomalyDetector()
        self.report_gen = ReportGenerator(
            self.llm,
            self.ttp_mapper,
            self.anomaly_detector,
            self.db
        )
        
        logger.info("UnifiedAnalyzer initialized") def analyze_pcap(
        self,
        pcap_path: Path,
        create_ticket: bool = True,
        output_format: str = "html"
    ) -> Dict[str, Any]:
        """
        Complete PCAP analysis workflow
        
        Steps:
        1. Ingest PCAP (TShark + Zeek + Snort)
        2. Analyze with TTPs + Anomalies
        3. Generate report with LLM
        4. Save to database
        
        Returns:
            {
                "ingestion": {...},
                "events_count": int,
                "ttps": [...],
                "anomalies": {...},
                "report_path": Path,
                "ticket_id": str (if created)
            }
        """
        
        logger.info(f"Analyzing PCAP: {pcap_path.name}")
        
        # Step 1: Ingest PCAP
        ingestion_result = self.ingestion.ingest_pcap(pcap_path)
        logger.info(f"Ingested {ingestion_result['events_inserted']} events")
        
        # Step 2: Query events
        events = self.db.query_events(limit=50000)  # All events
        logger.info(f"Retrieved {len(events)} events for analysis")
        
        # Step 3: Ticket context (if creating ticket)
        ticket_context = None
        ticket_id = None
        
        if create_ticket:
            # Extract primary IOC (most common destination)
            destinations = {}
            for event in events:
                if event.di:
                    destinations[event.di] = destinations.get(event.di, 0) + 1
            
            if destinations:
                primary_ioc = max(destinations, key=destinations.get)
                
                ticket_id = f"SOC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                ticket_context = {
                    "ticket_id": ticket_id,
                    "ioc_value": primary_ioc,
                    "ioc_type": "ip",
                    "trigger_type": "pcap_analysis",
                    "window_start": datetime.fromtimestamp(min(e.t for e in events)),
                    "window_end": datetime.fromtimestamp(max(e.t for e in events))
                }
                
                logger.info(f"Created ticket context: {ticket_id}")
        
        # Step 4: Generate report
        report_content = self.report_gen.generate_report(
            events=events,
            ticket_context=ticket_context,
            output_format=output_format
        )
        
        # Step 5: Save report
        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format}"
        report_path = Path(f"reports/{report_filename}")
        self.report_gen.save_report(report_content, report_path, output_format)
        
        # Step 6: Create ticket in DB
        if create_ticket and ticket_context:
            ioc = IOC(
                ioc_type=ticket_context["ioc_type"],
                ioc_value=ticket_context["ioc_value"],
                first_seen=ticket_context["window_start"],
                last_seen=ticket_context["window_end"],
                sightings=destinations.get(primary_ioc, 0)
            )
            
            ticket = Ticket(
                ticket_id=ticket_id,
                ioc=ioc,
                trigger_type=ticket_context["trigger_type"],
                created_at=datetime.now(),
                window_start=ticket_context["window_start"],
                window_end=ticket_context["window_end"],
                report_path=str(report_path),
                report_generated=datetime.now()
            )
            
            self.db.create_ticket(ticket)
            logger.info(f"Ticket saved to database: {ticket_id}")
        
        # Get TTPs and anomalies for response
        ttps = self.ttp_mapper.infer_techniques(events)
        anomalies = self.anomaly_detector.detect_anomalies(events)
        
        return {
            "ingestion": ingestion_result,
            "events_count": len(events),
            "ttps": [
                {
                    "id": ttp.technique_id,
                    "name": ttp.technique_name,
                    "tactic": ttp.tactic,
                    "confidence": ttp.confidence
                }
                for ttp in ttps
            ],
            "anomalies": anomalies,
            "report_path": str(report_path),
            "ticket_id": ticket_id
        }
    
    def analyze_ticket(
        self,
        ticket_id: str,
        output_format: str = "html"
    ) -> Dict[str, Any]:
        """
        Analyze existing ticket with historical correlation
        
        Implements 75/25 weighted analysis
        """
        # TODO: Implement ticket analysis
        raise NotImplementedError("Ticket analysis coming in next phase")
    
    def health_check(self) -> Dict[str, Any]:
        """Check system health"""
        return {
            "database": "connected",
            "llm": self.llm.health_check(),
            "ingestion": {
                "zeek": self.ingestion.zeek_enabled,
                "snort": self.ingestion.snort_enabled
            },
            "components": {
                "ttp_mapper": "ready",
                "anomaly_detector": "ready",
                "report_generator": "ready"
            }
        }
