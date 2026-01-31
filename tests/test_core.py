"""
Basic validation tests for SOC_Intelligence core components
"""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.unified.models.schemas import TOONEvent, WeightedThreatScore
from src.unified.db.duckdb_adapter import DuckDBAdapter
from src.unified.analysis.ttp_mapper import TTPMapper
from src.unified.analysis.anomaly_detector import AnomalyDetector


def test_toon_event_creation():
    """Test TOON event model"""
    event = TOONEvent(
        t=1706732400.0,
        si="192.168.1.100",
        sp=54321,
        di="8.8.8.8",
        dp=53,
        pr="dns",
        dns_query="google.com"
    )
    
    assert event.si == "192.168.1.100"
    assert event.pr == "dns"
    assert event.dns_query == "google.com"


def test_duckdb_adapter():
    """Test DuckDB adapter initialization"""
    db = DuckDBAdapter("data/test_db.duckdb")
    assert db.conn is not None
    
    # Test event insertion
    events = [
        TOONEvent(
            t=1706732400.0 + i,
            si="192.168.1.100",
            di="8.8.8.8",
            pr="dns"
        )
        for i in range(10)
    ]
    
    inserted = db.insert_events(events)
    assert inserted == 10
    
    # Test query
    queried = db.query_events(limit=10)
    assert len(queried) == 10
    
    db.close()


def test_ttp_mapper():
    """Test TTP mapping"""
    mapper = TTPMapper()
    
    # Create beaconing pattern
    events = [
        TOONEvent(
            t=1706732400.0 + (i * 60),  # Every 60 seconds
            si="192.168.1.100",
            sp=50000 + i,
            di="10.0.0.5",
            dp=443,
            pr="tcp"
        )
        for i in range(10)
    ]
    
    ttps = mapper.infer_techniques(events)
    
    # Should detect beaconing
    assert any(ttp.technique_id == "T1071" for ttp in ttps)


def test_anomaly_detector():
    """Test anomaly detection"""
    detector = AnomalyDetector()
    
    # Create port scan pattern
    events = [
        TOONEvent(
            t=1706732400.0 + i,
            si="192.168.1.100",
            di="10.0.0.5",
            dp=80 + i,
            pr="tcp"
        )
        for i in range(50)
    ]
    
    anomalies = detector.detect_anomalies(events)
    
    # Should detect port scan
    assert len(anomalies['port_scans']) > 0


def test_weighted_threat_score():
    """Test 75/25 weighted scoring"""
    score = WeightedThreatScore(
        current_volume_score=0.8,
        current_diversity_score=0.7,
        current_pattern_score=0.9,
        current_window_score=0.8,
        tp_count=5,
        fp_count=2,
        historical_threat_ratio=5/7,
        historical_score=5/7
    )
    
    # Verify weighting
    expected = (0.75 * 0.8) + (0.25 * (5/7))
    assert abs(score.weighted_score - expected) < 0.01
    
    # Should be threat-consistent
    assert score.assessment == "THREAT-CONSISTENT"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
