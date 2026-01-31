#!/usr/bin/env python3
"""
Simple Flask server for One_Blink dashboard UI testing
Serves static files and provides mock API endpoints
"""

from flask import Flask, render_template, jsonify, request, send_from_directory, send_file
from datetime import datetime
import json
import random
import logging
import os
from pathlib import Path
import shutil
import io

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.FileHandler('logs/error.log', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create logs directory
Path('logs').mkdir(exist_ok=True)

# Mock data for testing
def generate_mock_dashboard_data():
    """Generate mock data for dashboard"""
    
    # Traffic volume
    traffic_volume = {
        'labels': [f'{h:02d}:00' for h in range(0, 24, 2)],
        'volumes': [random.uniform(10, 50) for _ in range(12)]
    }
    
    # Protocol distribution
    protocol_distribution = {
        'protocols': ['HTTP', 'TLS', 'DNS', 'TCP', 'UDP'],
        'counts': [4500, 3200, 1800, 950, 500]
    }
    
    # Risk timeline
    risk_timeline = {
        'time_buckets': [f'{h:02d}:00' for h in range(0, 24, 4)],
        'high_risk': [random.randint(2, 12) for _ in range(6)],
        'suspicious': [random.randint(10, 30) for _ in range(6)],
        'normal': [random.randint(60, 100) for _ in range(6)]
    }
    
    # Top talkers
    top_talkers = {
        'ips': [f'192.168.1.{100+i}' for i in range(5)],
        'packet_counts': [15420, 12350, 9870, 7540, 6230]
    }
    
    # Connection states
    connection_states = {
        'states': ['SF', 'S0', 'REJ', 'RSTO', 'Other'],
        'counts': [8500, 2340, 1250, 890, 520]
    }
    
    # MITRE heatmap
    mitre_heatmap = {
        'tactics': ['Initial Access', 'Execution', 'Persistence', 'Discovery', 'Exfiltration'],
        'technique_counts': [3, 5, 2, 7, 1]
    }
    
    # Generate mock events
    events = []
    for i in range(100):
        events.append({
            'id': i + 1,
            't': datetime.now().timestamp() - (i * 300),
            'si': f'192.168.1.{100 + random.randint(0, 50)}',
            'di': f'10.0.0.{50 + random.randint(0, 50)}',
            'pr': random.choice(['tcp', 'udp', 'icmp']),
            'zeek_service': random.choice(['http', 'https', 'dns', 'ssh', None]),
            'alert_msg': 'Suspicious traffic' if random.random() > 0.9 else None
        })
    
    return {
        'charts': {
            'traffic_volume': traffic_volume,
            'protocol_distribution': protocol_distribution,
            'risk_timeline': risk_timeline,
            'top_talkers': top_talkers,
            'connection_states': connection_states,
            'mitre_heatmap': mitre_heatmap
        },
        'events': events,
        'metrics': {
            'total_events': 27544,
            'unique_sources': 142,
            'high_risk': 23,
            'data_volume': '1.2 GB'
        }
    }

# Routes
@app.route('/')
def index():
    """Upload page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route('/reports')
def reports():
    """Reports gallery page"""
    return render_template('reports.html')

@app.route('/settings')
def settings():
    """Settings and administration page"""
    return render_template('settings.html')

# API endpoints
@app.route('/api/dashboard')
def api_dashboard():
    """Get dashboard data"""
    data = generate_mock_dashboard_data()
    return jsonify(data)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Handle PCAP upload and analysis"""
    # Mock response
    return jsonify({
        'status': 'success',
        'ticket_id': f'TKT-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
        'message': 'Analysis started (mock)'
    })

@app.route('/api/reports')
def api_reports():
    """Get list of reports"""
    reports = [
        {
            'id': f'RPT-20260131-210500',
            'created_at': '2026-01-31T21:05:00',
            'verdict': 'MALICIOUS',
            'events_count': 27544,
            'confidence': 0.87,
            'ttps_count': 12,
            'alerts_count': 43
        },
        {
            'id': f'RPT-20260131-203000',
            'created_at': '2026-01-31T20:30:00',
            'verdict': 'SUSPICIOUS',
            'events_count': 15220,
            'confidence': 0.62,
            'ttps_count': 7,
            'alerts_count': 18
        },
        {
            'id': f'RPT-20260131-195500',
            'created_at': '2026-01-31T19:55:00',
            'verdict': 'BENIGN',
            'events_count': 8432,
            'confidence': 0.92,
            'ttps_count': 0,
            'alerts_count': 0
        }
    ]
    return jsonify(reports)

@app.route('/api/generate-report', methods=['POST'])
def api_generate_report():
    """Generate new report"""
    logger.info('Generating new report')
    return jsonify({
        'status': 'success',
        'report_id': f'RPT-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
    })

# Admin API endpoints
@app.route('/api/system/stats')
def api_system_stats():
    """Get system statistics"""
    return jsonify({
        'total_events': random.randint(10000, 50000),
        'total_reports': random.randint(10, 50),
        'database_size': '125 MB',
        'uptime': '2h 15m'
    })

@app.route('/api/database/reset', methods=['POST'])
def api_database_reset():
    """Reset database - delete all data"""
    logger.warning('DATABASE RESET REQUESTED')
    try:
        # In production, this would delete DuckDB database
        # For now, just log the action
        logger.info('Database reset executed')
        return jsonify({
            'status': 'success',
            'message': 'Database reset successfully',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f'Database reset failed: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/logs/download')
def api_logs_download():
    """Download log files"""
    log_type = request.args.get('type', 'app')
    log_file = f'logs/{log_type}.log'
    
    if not os.path.exists(log_file):
        # Create sample log if doesn't exist
        with open(log_file, 'w') as f:
            f.write(f'One_Blink {log_type.upper()} Logs\n')
            f.write('=' * 60 + '\n')
            f.write(f'{datetime.now().isoformat()} - System started\n')
            f.write(f'{datetime.now().isoformat()} - Flask server initialized\n')
            if log_type == 'error':
                f.write(f'{datetime.now().isoformat()} - ERROR: Sample error for testing\n')
    
    return send_file(log_file, as_attachment=True, download_name=f'oneblink_{log_type}.log')

@app.route('/api/logs/live')
def api_logs_live():
    """Get live log entries"""
    log_file = 'logs/app.log'
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            lines = f.readlines()
            recent_lines = lines[-50:]  # Last 50 lines
    else:
        recent_lines = ['No logs available yet']
    
    return jsonify({
        'status': 'success',
        'entries': recent_lines
    })

@app.route('/api/cache/clear', methods=['POST'])
def api_cache_clear():
    """Clear cache"""
    logger.info('Cache clear requested')
    try:
        # In production, clear actual cache
        cache_dir = Path('cache')
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
            cache_dir.mkdir()
        
        return jsonify({
            'status': 'success',
            'message': 'Cache cleared successfully'
        })
    except Exception as e:
        logger.error(f'Cache clear failed: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/export/<data_type>')
def api_export(data_type):
    """Export data"""
    logger.info(f'Export requested: {data_type}')
    
    if data_type == 'events':
        # Generate sample JSON export
        data = {
            'export_date': datetime.now().isoformat(),
            'total_events': 100,
            'events': [
                {'id': i, 'timestamp': datetime.now().isoformat(), 'type': 'sample'}
                for i in range(10)
            ]
        }
        
        output = io.BytesIO()
        output.write(json.dumps(data, indent=2).encode())
        output.seek(0)
        
        return send_file(output, as_attachment=True, download_name='events_export.json', mimetype='application/json')
    
    elif data_type == 'reports':
        # For ZIP, would need to package all reports
        return jsonify({'status': 'error', 'message': 'ZIP export not implemented'}), 501
    
    return jsonify({'status': 'error', 'message': 'Invalid export type'}), 400

@app.route('/api/database/backup', methods=['POST'])
def api_database_backup():
    """Create database backup"""
    logger.info('Database backup requested')
    try:
        backup_file = f'backups/db_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        Path('backups').mkdir(exist_ok=True)
        
        # In production, copy actual database
        # For now, create placeholder
        with open(backup_file, 'w') as f:
            f.write('Database backup placeholder')
        
        return jsonify({
            'status': 'success',
            'message': 'Backup created successfully',
            'backup_file': backup_file
        })
    except Exception as e:
        logger.error(f'Backup failed: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    print("=" * 60)
    print("One_Blink Dashboard Server")
    print("=" * 60)
    print("\nStarting server...")
    print("Dashboard will open in browser automatically")
    print("\nAvailable pages:")
    print("  - Upload:    http://localhost:5000/")
    print("  - Dashboard: http://localhost:5000/dashboard")
    print("  - Reports:   http://localhost:5000/reports")
    print("\nPress Ctrl+C to stop server")
    print("=" * 60)
    
    # Open browser after short delay
    import threading
    import webbrowser
    import time
    
    def open_browser():
        time.sleep(1.5)
        webbrowser.open('http://localhost:5000/')
    
    threading.Thread(target=open_browser).start()
    
    # Run Flask
    app.run(host='0.0.0.0', port=5000, debug=False)
