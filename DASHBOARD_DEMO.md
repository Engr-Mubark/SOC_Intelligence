# One_Blink Dashboard - Live Demo Guide

## Server Running ✅

**Flask Server Status:** ACTIVE  
**URL:** http://localhost:5000/  
**Port:** 5000

---

## Available Pages

### 1. Upload Page
**URL:** `http://localhost:5000/`  
**Features:**
- Drag-and-drop PCAP upload zone
- File validation (type and size)
- Analysis options:
  - ✓ Enable Zeek enrichment
  - ✓ Enable Snort IDS
  - ✓ Generate AI analysis report
- Progress bar with 7 stages
- System status metric cards

### 2. Dashboard Page
**URL:** `http://localhost:5000/dashboard`  
**Features:**
- 4 KPI metric cards (Total Events, Unique Sources, High Risk, Data Volume)
- TLP classification banner
- 6 interactive Chart.js visualizations:
  1. Traffic Volume Over Time (Line chart)
  2. Protocol Distribution (Doughnut chart)
  3. Risk Timeline (Stacked bar chart)
  4. Top Talkers (Horizontal bar chart)
  5. Connection States (Polar area chart)
  6. MITRE ATT&CK Coverage (Bar chart)
- TOON events data table
- Filtering and sorting
- CSV/JSON export buttons

### 3. Reports Gallery
**URL:** `http://localhost:5000/reports`  
**Features:**
- Report cards grid
- Verdict-based color coding (red/amber/green)
- Report statistics display
- View/Download actions
- 3 sample reports pre-loaded

---

## API Endpoints (Mock Data)

All endpoints are working with simulated data:

- `GET /api/dashboard` - Returns chart data and metrics
- `POST /api/analyze` - Handles PCAP upload (mock)
- `GET /api/reports` - Returns list of reports
- `POST /api/generate-report` - Creates new report

---

## How to Use

1. **Open browser** to http://localhost:5000/
2. **Navigate** between pages using top navigation
3. **View charts** on dashboard page (auto-generated with mock data)
4. **Explore reports** in reports gallery
5. **Test upload** (mock response, no actual processing)

---

## Server Management

**To stop server:** Press Ctrl+C in the terminal

**To restart server:**
```bash
cd /home/mark/Desktop/training/One_Blink/One_Blink_New
python3 server.py
```

---

## Notes

- Server is using **mock data** for testing
- Charts are fully interactive (hover, zoom, legend toggle)
- Dashboard updates automatically on page load
- All JavaScript and CSS files loading correctly
- No errors in console

---

## Next Steps

To connect to real PCAP analysis:
1. Integrate with `unified_analyzer.py`
2. Replace mock API endpoints with real data
3. Add file upload handling
4. Connect to DuckDB for actual events

**Dashboard UI is fully functional and ready for integration!**
