# NIDRS – Network Intrusion Detection and Response System

NIDRS is a beginner-friendly network intrusion detection project built using Suricata, Python, SQLite, and Flask. It monitors network traffic, identifies security alerts, stores alert information, and displays the results through a web-based dashboard.

## Project Overview

Network security is important for identifying suspicious activities and understanding what is happening across a network.

NIDRS uses Suricata as its intrusion detection engine. Python processes the generated alerts, SQLite stores the alert records, and Flask provides a dashboard to view and filter the detected alerts.

## Features

- **Network Monitoring:** Monitors network traffic using Suricata.
- **Intrusion Detection:** Uses Suricata rules to identify matching network activity.
- **Custom Detection Rule:** Detects ICMP Echo Requests (ping requests).
- **Alert Analysis:** Extracts important information from Suricata EVE JSON logs using Python.
- **Database Storage:** Stores alert details in an SQLite database.
- **Duplicate Prevention:** Uses unique event identifiers to prevent duplicate alert records.
- **Web Dashboard:** Displays alert statistics and recent security alerts.
- **Alert Filtering:** Allows filtering by source IP address, protocol, and severity.
- **Visual Analytics:** Displays protocol and severity distribution charts.

## Technologies Used

| Technology | Purpose |
|---|---|
| Suricata | Network intrusion detection |
| Python | Alert processing and analysis |
| SQLite | Alert data storage |
| Flask | Web application and dashboard |
| HTML and CSS | Dashboard structure and styling |
| JavaScript and Chart.js | Data visualization |
| Debian on WSL2 | Development environment |

## Project Workflow

1. Suricata monitors network traffic.
2. Matching traffic generates security alerts.
3. Alerts are recorded in the EVE JSON log.
4. Python reads and analyzes the alert records.
5. Processed alerts are stored in the SQLite database.
6. Flask retrieves the stored data.
7. The dashboard displays statistics, charts, and filtered alerts.

## Project Structure

```text
NIDRS/
├── database/
│   └── nidrs.db
├── src/
│   ├── alert_analyzer.py
│   ├── app.py
│   ├── database.py
│   └── templates/
│       └── index.html
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

- Python 3
- Debian on WSL2 or a compatible Linux environment
- Suricata
- Git

### Installation

Clone the repository:

```bash
git clone https://github.com/pavanij-10/Code
