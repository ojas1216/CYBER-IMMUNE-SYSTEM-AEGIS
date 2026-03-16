# CYBER-IMMUNE-SYSTEM-AEGIS
Autonomous Defense & Adversarial Posture Tester

Overview
AEGIS-ADAPT creates a continuous "cyber immune system" by automatically generating and testing blue team defenses based on red team findings in real-time. It establishes a closed feedback loop between offensive and defensive security operations.

#IMPORTANT LEGAL DISCLAIMER
- THIS TOOL IS PROVIDED FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY.

- By downloading, installing, or using this software, you acknowledge and agree that:

- YOU ARE SOLELY RESPONSIBLE for ensuring your use complies with all applicable local, state, federal, and international laws.

- YOU MUST OBTAIN EXPLICIT WRITTEN PERMISSION before testing any systems you do not own.

- UNAUTHORIZED USE including scanning, attacking, or penetrating systems without permission is ILLEGAL and strictly prohibited.

- THE AUTHOR ASSUMES NO LIABILITY for any misuse, damages, or legal consequences arising from your use of this software.

- THE AUTHOR IS NOT RESPONSIBLE for any illegal activities conducted with this tool.

- IF YOU DO NOT AGREE with these terms, do not download, install, or use this software.

## Architecture
```bash
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Red Team      │    │    Analyzer     │    │   Blue Team     │
│    Engine       │───▶│     Engine      │───▶│     Engine      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                      │                      │
         ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Feedback Loop Controller                    │
│         (Variant Generation → Testing → Tuning)              │
└─────────────────────────────────────────────────────────────┘
```
## Key Features
- 200+ attack scenarios across 8 MITRE ATT&CK phases

- RAG-based retrieval (ChromaDB + FAISS) for intelligent technique selection

- Multi-format rule generation: Sigma, YARA, Suricata, Splunk, Elastic, ModSecurity

- Automated feedback loop: Generates variants, tests detection, tunes rules to 95%+ accuracy

- Continuous monitoring: 24/7 autonomous operation with gap alerting

- LLM integration: Ollama (primary) + Gemini (fallback) for command generation

## Quick Install
```bash
# Clone and setup
git clone https://github.com/yourusername/CYBER-IMMUNE-SYSTEM-AEGIS.git
cd CYBER-IMMUNE-SYSTEM-AEGIS

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your settings

# Run
python aegis_adapt.py
Required External Tools

# Install Nmap (Windows)
# Download from: https://nmap.org/download.html

# Install Nmap (Linux)
sudo apt-get install nmap

# Install SQLMap
pip install sqlmap

# Install GoBuster (Linux)
sudo apt-get install gobuster

# Install GoBuster (Windows)
# Download from: https://github.com/OJ/gobuster/releases
Basic Usage

# Start interactive mode
python aegis_adapt.py

# Quick scan
python aegis_adapt.py --target scanme.nmap.org
```

## Required External Tools

For full functionality, install these security tools:
```bash
| Tool | Purpose | Installation |
|------|---------|--------------|
| Nmap | Port scanning | [nmap.org](https://nmap.org/download.html) |
| SQLMap | SQL injection | `pip install sqlmap` |
| GoBuster | Directory enumeration | [GitHub](https://github.com/OJ/gobuster/releases) |
| Masscan | Fast port scanning | [GitHub](https://github.com/robertdavidgraham/masscan) |
| Amass | DNS enumeration | [GitHub](https://github.com/OWASP/Amass) |
| Hydra | Password brute-forcing | [GitHub](https://github.com/vanhauser-thc/thc-hydra) |
| TheHarvester | Email/subdomain gathering | `pip install theHarvester` |
| Nikto | Web server scanner | [GitHub](https://github.com/sullo/nikto) |
```

## Help
```bash
python aegis_adapt.py --help
CLI Commands
text
scan <target>           - Run reconnaissance and find vulnerabilities
analyze                 - Map findings to MITRE and generate initial rules
test                    - Launch attack variants against generated rules
tune                    - Auto-improve rules based on test results
heatmap                 - Show MITRE ATT&CK coverage visualization
export <format>         - Export rules or reports (html, json, csv, sigma, yara)
monitor <target>        - Start continuous mode
monitor stop            - Stop continuous monitoring
status                  - Show system status and metrics
history                 - Show past scan results
config                  - Display current configuration
exit                    - Quit the application
help                    - Show this help message
```
## Example Workflow
```bash
# Start the tool
python aegis_adapt.py

# Scan a target
aegis-adapt> scan scanme.nmap.org

# Analyze findings
aegis-adapt> analyze

# Test detection rules
aegis-adapt> test

# View coverage heatmap
aegis-adapt> heatmap

# Export HTML report
aegis-adapt> export html

# Export JSON data
aegis-adapt> export json

# Exit

aegis-adapt> exit 
```
## Output Formats
- HTML Reports: Executive summaries with heatmaps and findings

- JSON/CSV: Machine-readable data export

- Sigma Rules: YAML format for SIEM integration

- YARA Rules: Malware pattern matching

- Suricata Rules: Network IDS signatures

- Splunk SPL: Search queries

- Elastic DSL: Elasticsearch queries

- ModSecurity Rules: WAF rules

- Remediation Code: Python, PowerShell, Bash

## Project Structure
```bash
CYBER-IMMUNE-SYSTEM-AEGIS/
├── aegis_adapt.py          # Main application
├── attack_scenarios.json   # 200+ attack scenarios
├── requirements.txt        # Python dependencies
├── .env.example            # Example configuration
├── .gitignore              # Git ignore rules
├── README.md               # This file
├── LICENSE.txt             # License agreement
├── data/                   # SQLite database
├── logs/                   # Log files
├── output/                 # Exported reports
└── rules/                  # Generated detection rules
```
## Configuration (.env)
```bash
# Paths
DATASET_PATH=attack_scenarios.json
DATABASE_PATH=data/aegis_adapt.db
CHROMA_PATH=chroma_data
FAISS_INDEX_PATH=faiss_index/index.faiss

# LLM Settings (optional)
OLLAMA_MODEL=llama2
GEMINI_API_KEY=your_api_key_here

# Performance
MAX_WORKERS=10
VARIANT_COUNT=10
DETECTION_THRESHOLD=0.95
UPDATE_INTERVAL=3600

# Logging
LOG_LEVEL=INFO

```

## Troubleshooting

 Check installed tools
```bash
where nmap  # Windows
which nmap  # Linux/Mac
```
### Reset database
```bash
rm data/aegis_adapt.db
```
### Update dependencies
```bash
pip install --upgrade -r requirements.txt
```
### Test imports
```bash
python -c "import numpy; import pandas; print('OK')"
```

## License
Copyright (c) 2026 Ojas Satardekar. All rights reserved. See LICENSE.txt for terms.

# LEGAL RESPONSIBILITY
- THE USER ASSUMES ALL RESPONSIBILITY FOR THEIR ACTIONS.

- The author of this software:

- Provides this tool for educational purposes only

- Does not condone or encourage illegal activity

- Is not responsible for any misuse or damages

- Will not be held liable for any legal consequences arising from use

- Disclaims all warranties, express or implied

By using this software, you acknowledge that you are solely responsible for complying with all applicable laws and regulations. If you cannot accept this responsibility, do not use this software.

# Contact
Ojas Satardekar - ojas191025@gmail.com

