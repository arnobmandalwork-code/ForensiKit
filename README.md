# ForensiKit - Digital Forensics Toolkit

ForensiKit is a beginner-friendly Python digital forensics toolkit. It was built as a student cybersecurity project to demonstrate file recovery, hashing, metadata extraction, suspicious file scanning, log analysis, and report generation.

## Features

- Recover files from raw binary data using file signatures
- Generate MD5, SHA1, and SHA256 hashes
- Extract basic file metadata
- Scan folders for suspicious files
- Analyze logs for suspicious keywords
- Create a forensic report
- Simple Tkinter GUI

## How to Run

```bash
python3 main.py
```

## Why This Project Matters

Digital forensics is important in cybersecurity because investigators often need to analyze files, recover deleted data, verify evidence integrity, and document findings. This project simulates those workflows at a beginner level.

## Tools Used

- Python
- Tkinter
- hashlib
- os
- datetime

## Future Improvements

- Add more file signatures
- Add PDF report export
- Add image EXIF extraction
- Add timeline visualization
- Add Sleuth Kit command integration
