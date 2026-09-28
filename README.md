# Ransomware Early Warning System

A ransomware early warning system developed as part of an advanced internship project.

The system monitors filesystem activity and assigns a risk score based on suspicious file behavior. It provides a live dashboard to observe activity and identify possible ransomware-like behavior.

## My Contribution

My work focuses on the base detection system and the monitoring interface.

- Implemented real-time filesystem monitoring using Python and Watchdog
- Added heuristic risk scoring for suspicious file activity
- Monitored file creation, modification, deletion, and renaming events
- Added detection for suspicious ransomware-related file extensions
- Implemented risk score decay over time
- Added configurable risk thresholds for different alert levels
- Built the real-time monitoring dashboard
- Added live activity logs and risk visualization
- Added controls for selecting the folder to monitor and starting/stopping monitoring
- Added a safe test-data generator for testing the detection system

## Technologies

- Python
- Watchdog
- Tkinter / ttkbootstrap
- Matplotlib

## How It Works

The system watches a selected directory and processes filesystem events as they occur.

Different activities contribute different amounts to the risk score. For example, repeated file modifications, deletions, renaming, or suspicious extensions increase the score. The score gradually decreases when suspicious activity stops.

When the score crosses a configured threshold, the dashboard displays a corresponding risk status.

## Running the Project

Install the required packages:

```bash
python -m pip install -r requirements.txt
