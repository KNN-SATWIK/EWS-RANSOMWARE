# NEON//RANSOMWARE EWS — Live Detector

This version is a REAL Windows filesystem-behavior detector for a user-selected test directory.

## What is real

The program uses `watchdog` to observe the selected folder recursively. It receives actual operating-system filesystem events:

- file creation
- file modification
- file deletion
- file rename/move

The detector then applies heuristic weights and a time-decay window.

It does NOT simulate these events.

## Detection logic

| Real event | Base score |
|---|---:|
| CREATED | +2 |
| MODIFIED | +3 |
| DELETED | +15 |
| RENAMED | +25 |
| Suspicious ransomware extension | +45 |
| Rapid modification burst | +20 |

Suspicious extensions include examples such as `.locked`, `.encrypted`, `.enc`, `.wncry`, `.locky`, `.crypted`, etc.

Default alert threshold: 150.
Default decay window: 10 seconds.

The current score is the sum of active event scores still inside the decay window.

## Safe test workflow

1. Run the application.
2. Click `SELECT FOLDER`.
3. Select a dedicated empty test folder.
4. Click `CREATE TEST DATA`.
5. Click `START LIVE MONITOR`.
6. Copy/edit/rename/delete the sample files.
7. Watch the real events appear in the event stream and graph.

For a stronger ransomware-like detection demonstration, rapidly rename several COPY files to a harmless extension such as `.locked`. The program detects the real rename operations and recognizes `.locked` as suspicious.

DO NOT run ransomware samples and DO NOT test against your real Documents, Desktop, system directories, or backups.

## Installation

Open PowerShell in this folder:

```powershell
python -m pip install -r requirements.txt
python ransomware_ews_live.py
```

If `python` is not available, try:

```powershell
py -m pip install -r requirements.txt
py ransomware_ews_live.py
```

## Project scope

This implements:

- Base behavioral detection
- Real filesystem monitoring
- Time-decay risk scoring
- Real-time alerting
- Enhancement 1: Proper neon cyberpunk tool GUI

Intentionally NOT implemented:

2. AI-Based Adaptive Detection
3. Deception Environment / Honeypots
4. Threat Feed Updates
5. Blockchain Logging + User Awareness

Those remain extension points for the other four group members.
