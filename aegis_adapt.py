"""
AEGIS-ADAPT: Autonomous Defense & Adversarial Posture Tester
Copyright (c) 2026 Ojas Satardekar
Contact: ojas191025@gmail.com
Proprietary License - All rights reserved
"""

import os
import sys
import json
import sqlite3
import hashlib
import time
import datetime
import threading
import queue
import subprocess
import shlex
import logging
import argparse
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from enum import Enum
import re
import base64
import urllib.parse
import random
import string

# Third-party imports with error handling
try:
    import numpy as np
    import pandas as pd
    from sklearn.metrics import precision_score, recall_score, f1_score
    import yaml
    from dotenv import load_dotenv
    from loguru import logger
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    print(f"Critical import error: {e}")
    print("Please install required dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Optional imports with graceful fallbacks
try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    logger.warning("ChromaDB not available, using fallback mode")

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("FAISS not available, using fallback mode")

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    logger.warning("Ollama not available")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logger.warning("Gemini not available")

# Load environment variables
load_dotenv()

# Configuration class
class Config:
    DATASET_PATH = os.getenv('DATASET_PATH', 'attack_scenarios.json')
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'data/aegis_adapt.db')
    CHROMA_PATH = os.getenv('CHROMA_PATH', 'chroma_data')
    FAISS_INDEX_PATH = os.getenv('FAISS_INDEX_PATH', 'faiss_index/index.faiss')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama2')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-pro')
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', '10'))
    VARIANT_COUNT = int(os.getenv('VARIANT_COUNT', '10'))
    DETECTION_THRESHOLD = float(os.getenv('DETECTION_THRESHOLD', '0.95'))
    UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL', '3600'))
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
    MAX_RETRIES = int(os.getenv('MAX_RETRIES', '3'))

# Attack phases enum
class AttackPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DEFENSE_EVASION = "defense_evasion"
    EXFILTRATION = "exfiltration"

# Rule types enum
class RuleType(Enum):
    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    WAZUH = "wazuh"
    MODSECURITY = "modsecurity"
    CODE_PYTHON = "code_python"
    CODE_POWERSHELL = "code_powershell"
    CODE_BASH = "code_bash"

# Database manager class
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Attacks table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS attacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        technique_id TEXT,
                        command TEXT,
                        output TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        target TEXT,
                        status TEXT
                    )
                ''')
                
                # Detections table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        attack_id INTEGER,
                        rule_type TEXT NOT NULL,
                        rule_content TEXT,
                        effectiveness REAL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (attack_id) REFERENCES attacks (id)
                    )
                ''')
                
                # Variants table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS variants (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        attack_id INTEGER,
                        variant_command TEXT,
                        encoding TEXT,
                        success BOOLEAN,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (attack_id) REFERENCES attacks (id)
                    )
                ''')
                
                # Rules table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        attack_id INTEGER,
                        rule_type TEXT NOT NULL,
                        rule_content TEXT,
                        version INTEGER DEFAULT 1,
                        detection_rate REAL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (attack_id) REFERENCES attacks (id)
                    )
                ''')
                
                # Metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id INTEGER,
                        test_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                        attacks_tested INTEGER,
                        detected INTEGER,
                        false_positives INTEGER,
                        precision REAL,
                        recall REAL,
                        f1_score REAL,
                        FOREIGN KEY (rule_id) REFERENCES rules (id)
                    )
                ''')
                
                # Coverage table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS coverage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        technique_id TEXT UNIQUE,
                        detection_count INTEGER DEFAULT 0,
                        last_tested DATETIME,
                        coverage_score REAL
                    )
                ''')
                
                # System log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        component TEXT,
                        level TEXT,
                        message TEXT
                    )
                ''')
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def execute_query(self, query: str, params: tuple = ()) -> Optional[List[Dict]]:
        """Execute a query and return results as list of dictionaries"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                if query.strip().upper().startswith('SELECT'):
                    return [dict(row) for row in cursor.fetchall()]
                else:
                    conn.commit()
                    return None
                    
        except sqlite3.Error as e:
            logger.error(f"Query execution error: {e}")
            return None
    
    def insert_attack(self, attack_data: Dict) -> int:
        """Insert a new attack record"""
        query = '''
            INSERT INTO attacks (name, phase, technique_id, command, output, target, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        params = (
            attack_data.get('name', ''),
            attack_data.get('phase', ''),
            attack_data.get('technique_id', ''),
            attack_data.get('command', ''),
            attack_data.get('output', ''),
            attack_data.get('target', ''),
            attack_data.get('status', 'completed')
        )
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Insert attack error: {e}")
            return -1
    
    def update_metrics(self, rule_id: int, metrics: Dict):
        """Update metrics for a rule"""
        query = '''
            INSERT INTO metrics (rule_id, attacks_tested, detected, false_positives, precision, recall, f1_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        params = (
            rule_id,
            metrics.get('attacks_tested', 0),
            metrics.get('detected', 0),
            metrics.get('false_positives', 0),
            metrics.get('precision', 0.0),
            metrics.get('recall', 0.0),
            metrics.get('f1_score', 0.0)
        )
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Update metrics error: {e}")

# RAG Manager for intelligent retrieval
class RAGManager:
    def __init__(self, config: Config):
        self.config = config
        self.chroma_client = None
        self.faiss_index = None
        self.encoder = None
        self.collection = None
        self.initialize()
    
    def initialize(self):
        """Initialize RAG components"""
        try:
            # Initialize ChromaDB with new API
            if CHROMA_AVAILABLE:
                try:
                    import chromadb
                    # Use the new PersistentClient API
                    self.chroma_client = chromadb.PersistentClient(
                        path=self.config.CHROMA_PATH
                    )
                    # Get or create collection
                    self.collection = self.chroma_client.get_or_create_collection(
                        name="attack_patterns"
                    )
                    logger.info("ChromaDB initialized successfully with new API")
                except Exception as e:
                    logger.warning(f"ChromaDB initialization failed: {e}")
            
            # Initialize FAISS
            if FAISS_AVAILABLE:
                try:
                    self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
                    if os.path.exists(self.config.FAISS_INDEX_PATH):
                        self.faiss_index = faiss.read_index(self.config.FAISS_INDEX_PATH)
                    else:
                        self.faiss_index = faiss.IndexFlatL2(384)
                    logger.info("FAISS initialized successfully")
                except Exception as e:
                    logger.warning(f"FAISS initialization failed: {e}")
                    
        except Exception as e:
            logger.warning(f"RAG initialization warning: {e}")
    
    def add_attack_pattern(self, attack_id: str, description: str, metadata: Dict):
        """Add attack pattern to vector stores"""
        try:
            if self.collection and CHROMA_AVAILABLE:
                self.collection.add(
                    documents=[description],
                    metadatas=[metadata],
                    ids=[attack_id]
                )
            
            if self.encoder and self.faiss_index and FAISS_AVAILABLE:
                embedding = self.encoder.encode([description])
                self.faiss_index.add(embedding)
                faiss.write_index(self.faiss_index, self.config.FAISS_INDEX_PATH)
                
        except Exception as e:
            logger.error(f"Add attack pattern error: {e}")
    
    def search_similar_attacks(self, query: str, k: int = 5) -> List[Dict]:
        """Search for similar attack patterns"""
        results = []
        
        try:
            # Search in ChromaDB
            if self.collection and CHROMA_AVAILABLE:
                chroma_results = self.collection.query(
                    query_texts=[query],
                    n_results=k
                )
                if chroma_results and 'documents' in chroma_results:
                    for i, doc in enumerate(chroma_results['documents'][0]):
                        results.append({
                            'document': doc,
                            'metadata': chroma_results['metadatas'][0][i] if 'metadatas' in chroma_results else {},
                            'score': chroma_results['distances'][0][i] if 'distances' in chroma_results else 0
                        })
            
            # Search in FAISS
            if self.encoder and self.faiss_index and FAISS_AVAILABLE and not results:
                query_embedding = self.encoder.encode([query])
                distances, indices = self.faiss_index.search(query_embedding, k)
                # Note: Would need to map indices back to original data
                
        except Exception as e:
            logger.error(f"Search similar attacks error: {e}")
        
        return results

# LLM Manager for AI-powered operations
class LLMManager:
    def __init__(self, config: Config):
        self.config = config
        self.ollama_client = None
        self.gemini_model = None
        self.initialize()
    
    def initialize(self):
        """Initialize LLM clients"""
        try:
            if OLLAMA_AVAILABLE:
                self.ollama_client = ollama.Client()
            
            if GEMINI_AVAILABLE and self.config.GEMINI_API_KEY:
                genai.configure(api_key=self.config.GEMINI_API_KEY)
                self.gemini_model = genai.GenerativeModel(self.config.GEMINI_MODEL)
                
        except Exception as e:
            logger.error(f"LLM initialization error: {e}")
    
    def generate_command(self, prompt: str, context: str = "") -> str:
        """Generate attack command using LLM"""
        try:
            full_prompt = f"Context: {context}\n\nTask: {prompt}\n\nGenerate a specific, safe for testing, command:"
            
            # Try Ollama first
            if self.ollama_client and OLLAMA_AVAILABLE:
                response = self.ollama_client.generate(
                    model=self.config.OLLAMA_MODEL,
                    prompt=full_prompt
                )
                return response.get('response', '')
            
            # Fallback to Gemini
            elif self.gemini_model and GEMINI_AVAILABLE:
                response = self.gemini_model.generate_content(full_prompt)
                return response.text
            
            else:
                logger.warning("No LLM available, using fallback generation")
                return self.fallback_generate_command(prompt)
                
        except Exception as e:
            logger.error(f"Generate command error: {e}")
            return self.fallback_generate_command(prompt)
    
    def fallback_generate_command(self, prompt: str) -> str:
        """Fallback command generation when LLM is unavailable"""
        # Simple template-based generation
        templates = {
            "nmap": "nmap -sV -sC -p- {target}",
            "gobuster": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
            "sqlmap": "sqlmap -u {target} --dbs --batch",
            "hydra": "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh",
            "default": "echo 'Command generation failed - LLM unavailable'"
        }
        
        for key in templates:
            if key in prompt.lower():
                return templates[key].format(target="{target}")
        
        return templates['default']
    
    def analyze_finding(self, finding: Dict) -> Dict:
        """Analyze finding and provide recommendations"""
        try:
            prompt = f"""
            Analyze this security finding:
            Attack: {finding.get('name', 'Unknown')}
            Technique: {finding.get('technique_id', 'Unknown')}
            Description: {finding.get('description', '')}
            Command: {finding.get('command', '')}
            Output: {finding.get('output', '')}
            
            Provide:
            1. MITRE ATT&CK mapping
            2. Detection recommendations
            3. Remediation steps
            """
            
            if self.ollama_client and OLLAMA_AVAILABLE:
                response = self.ollama_client.generate(
                    model=self.config.OLLAMA_MODEL,
                    prompt=prompt
                )
                return {"analysis": response.get('response', ''), "source": "ollama"}
            
            elif self.gemini_model and GEMINI_AVAILABLE:
                response = self.gemini_model.generate_content(prompt)
                return {"analysis": response.text, "source": "gemini"}
            
            else:
                return {"analysis": "LLM unavailable for analysis", "source": "none"}
                
        except Exception as e:
            logger.error(f"Analyze finding error: {e}")
            return {"analysis": f"Analysis error: {e}", "source": "error"}

# Red Team Engine
class RedTeamEngine:
    def __init__(self, config: Config, db_manager: DatabaseManager, rag_manager: RAGManager, llm_manager: LLMManager):
        self.config = config
        self.db = db_manager
        self.rag = rag_manager
        self.llm = llm_manager
        self.attack_scenarios = self.load_attack_scenarios()
        self.tools = self.discover_tools()
    
    def load_attack_scenarios(self) -> List[Dict]:
        """Load attack scenarios from JSON file"""
        try:
            if os.path.exists(self.config.DATASET_PATH):
                with open(self.config.DATASET_PATH, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Attack scenarios file not found: {self.config.DATASET_PATH}")
                return []
        except Exception as e:
            logger.error(f"Load attack scenarios error: {e}")
            return []
    
    def discover_tools(self) -> Dict[str, bool]:
        """Discover available security tools with debug output"""
        print("\n[DEBUG] Starting tool discovery...")
        tools = {}
        tool_list = [
            'nmap', 'masscan', 'rustscan', 'naabu', 'theHarvester', 'amass',
            'dnsrecon', 'sublist3r', 'metasploit', 'searchsploit', 'sqlmap',
            'mimikatz', 'impacket', 'crackmapexec', 'psexec', 'wmiexec',
            'evil-winrm', 'ssh', 'scp', 'curl', 'wget'
        ]
        
        for tool in tool_list:
            try:
                if sys.platform == 'win32':
                    result = subprocess.run(
                        ['where', tool],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                else:
                    result = subprocess.run(
                        ['which', tool],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                
                tools[tool] = result.returncode == 0
                if tools[tool]:
                    print(f"  [DEBUG] ✓ {tool} found at: {result.stdout.strip()}")
                else:
                    print(f"  [DEBUG] ✗ {tool} not found")
                    
            except Exception as e:
                tools[tool] = False
                print(f"  [DEBUG] ✗ {tool} error: {e}")
        
        print(f"[DEBUG] Total tools available: {sum(tools.values())}/{len(tools)}")
        return tools
    
    def execute_command(self, command: str, timeout: int = 300) -> Tuple[str, str, int]:
        """Execute a system command safely"""
        try:
            # Sanitize command
            if sys.platform == 'win32':
                # Windows command
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                # Unix/Linux command
                args = shlex.split(command)
                process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode
            
        except subprocess.TimeoutExpired:
            process.kill()
            return "", "Command timeout", -1
        except Exception as e:
            return "", str(e), -1
    
    def scan_target(self, target: str) -> List[Dict]:
        """Run reconnaissance and vulnerability scanning"""
        findings = []
        
        # Phase 1: Reconnaissance
        recon_findings = self.run_reconnaissance(target)
        findings.extend(recon_findings)
        
        # Phase 2: Scanning
        scan_findings = self.run_scanning(target)
        findings.extend(scan_findings)
        
        # Phase 3: Exploitation (if vulnerabilities found)
        if any(f.get('phase') == 'scanning' for f in findings):
            exploit_findings = self.run_exploitation(target)
            findings.extend(exploit_findings)
        
        return findings
    
    def run_reconnaissance(self, target: str) -> List[Dict]:
        """Run reconnaissance phase"""
        findings = []
        
        recon_tools = {
            'theHarvester': f'theHarvester -d {target} -b all -f output.html',
            'amass': f'amass enum -d {target} -o amass_output.txt',
            'dnsrecon': f'dnsrecon -d {target} -t std',
            'sublist3r': f'sublist3r -d {target} -o subdomains.txt'
        }
        
        for tool_name, command in recon_tools.items():
            if self.tools.get(tool_name.lower(), False):
                stdout, stderr, returncode = self.execute_command(command, timeout=600)
                
                finding = {
                    'name': f'{tool_name} reconnaissance',
                    'phase': 'reconnaissance',
                    'technique_id': 'T1590' if tool_name == 'theHarvester' else 'T1595',
                    'command': command,
                    'output': stdout[:1000],  # Limit output size
                    'target': target,
                    'status': 'success' if returncode == 0 else 'failed',
                    'tool': tool_name
                }
                
                findings.append(finding)
                
                # Store in database
                attack_id = self.db.insert_attack(finding)
                
                # Add to RAG
                if attack_id > 0:
                    self.rag.add_attack_pattern(
                        str(attack_id),
                        f"{finding['name']} on {target}",
                        {'phase': 'reconnaissance', 'technique': finding['technique_id']}
                    )
        
        return findings
    
    def run_scanning(self, target: str) -> List[Dict]:
        """Run scanning phase"""
        findings = []
        
        scan_tools = {
            'nmap': f'nmap -sV -sC -p- {target}',
            'masscan': f'masscan -p1-65535 --rate=1000 {target}',
            'rustscan': f'rustscan -a {target} -- -sV',
            'naabu': f'naabu -host {target}'
        }
        
        for tool_name, command in scan_tools.items():
            if self.tools.get(tool_name.lower(), False):
                stdout, stderr, returncode = self.execute_command(command, timeout=1800)
                
                finding = {
                    'name': f'{tool_name} scan',
                    'phase': 'scanning',
                    'technique_id': 'T1046',
                    'command': command,
                    'output': stdout[:1000],
                    'target': target,
                    'status': 'success' if returncode == 0 else 'failed',
                    'tool': tool_name
                }
                
                findings.append(finding)
                attack_id = self.db.insert_attack(finding)
                
                if attack_id > 0:
                    self.rag.add_attack_pattern(
                        str(attack_id),
                        f"{finding['name']} on {target}",
                        {'phase': 'scanning', 'technique': finding['technique_id']}
                    )
        
        return findings
    
    def run_exploitation(self, target: str) -> List[Dict]:
        """Run exploitation phase"""
        findings = []
        
        exploit_tools = {
            'sqlmap': f'sqlmap -u http://{target} --dbs --batch',
            'metasploit': 'msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS {target}; run; exit"',
            'searchsploit': f'searchsploit {target}'
        }
        
        for tool_name, command in exploit_tools.items():
            if self.tools.get(tool_name.lower(), False):
                formatted_command = command.replace('{target}', target)
                stdout, stderr, returncode = self.execute_command(formatted_command, timeout=3600)
                
                finding = {
                    'name': f'{tool_name} exploitation',
                    'phase': 'exploitation',
                    'technique_id': 'T1203',
                    'command': formatted_command,
                    'output': stdout[:1000],
                    'target': target,
                    'status': 'success' if returncode == 0 else 'failed',
                    'tool': tool_name
                }
                
                findings.append(finding)
                attack_id = self.db.insert_attack(finding)
                
                if attack_id > 0:
                    self.rag.add_attack_pattern(
                        str(attack_id),
                        f"{finding['name']} on {target}",
                        {'phase': 'exploitation', 'technique': finding['technique_id']}
                    )
        
        return findings

# Analyzer Engine
class AnalyzerEngine:
    def __init__(self, config: Config, db_manager: DatabaseManager, llm_manager: LLMManager):
        self.config = config
        self.db = db_manager
        self.llm = llm_manager
        self.mitre_mapping = self.load_mitre_mapping()
    
    def load_mitre_mapping(self) -> Dict:
        """Load MITRE ATT&CK mapping"""
        # Simplified MITRE mapping
        return {
            'reconnaissance': {
                'T1590': 'Gather Victim Network Information',
                'T1595': 'Active Scanning',
                'T1592': 'Gather Victim Host Information'
            },
            'scanning': {
                'T1046': 'Network Service Scanning',
                'T1040': 'Network Sniffing'
            },
            'exploitation': {
                'T1203': 'Exploitation for Client Execution',
                'T1210': 'Exploitation of Remote Services'
            },
            'privilege_escalation': {
                'T1068': 'Exploitation for Privilege Escalation',
                'T1548': 'Abuse Elevation Control Mechanism'
            },
            'persistence': {
                'T1547': 'Boot or Logon Autostart Execution',
                'T1136': 'Create Account'
            },
            'lateral_movement': {
                'T1021': 'Remote Services',
                'T1080': 'Taint Shared Content'
            },
            'defense_evasion': {
                'T1027': 'Obfuscated Files or Information',
                'T1070': 'Indicator Removal'
            },
            'exfiltration': {
                'T1041': 'Exfiltration Over C2 Channel',
                'T1048': 'Exfiltration Over Alternative Protocol'
            }
        }
    
    def map_to_mitre(self, finding: Dict) -> str:
        """Map finding to MITRE ATT&CK technique ID"""
        phase = finding.get('phase', '')
        description = finding.get('output', '').lower()
        
        # Try LLM mapping first
        if self.llm:
            analysis = self.llm.analyze_finding(finding)
            # Parse technique ID from analysis (simplified)
            technique_match = re.search(r'T\d{4}', analysis.get('analysis', ''))
            if technique_match:
                return technique_match.group(0)
        
        # Fallback to rule-based mapping
        if phase in self.mitre_mapping:
            techniques = self.mitre_mapping[phase]
            # Simple keyword matching
            for tech_id, tech_name in techniques.items():
                if any(keyword in description for keyword in tech_name.lower().split()):
                    return tech_id
        
        return 'T1203'  # Default to exploitation
    
    def generate_detection_rules(self, finding: Dict) -> Dict[str, str]:
        """Generate detection rules in multiple formats"""
        rules = {}
        
        # Sigma rule
        rules[RuleType.SIGMA.value] = self.generate_sigma_rule(finding)
        
        # YARA rule
        rules[RuleType.YARA.value] = self.generate_yara_rule(finding)
        
        # Suricata rule
        rules[RuleType.SURICATA.value] = self.generate_suricata_rule(finding)
        
        # Splunk SPL
        rules[RuleType.SPLUNK.value] = self.generate_splunk_query(finding)
        
        # Elastic DSL
        rules[RuleType.ELASTIC.value] = self.generate_elastic_query(finding)
        
        # Wazuh rule
        rules[RuleType.WAZUH.value] = self.generate_wazuh_rule(finding)
        
        # ModSecurity rule
        rules[RuleType.MODSECURITY.value] = self.generate_modsecurity_rule(finding)
        
        # Remediation code
        rules[RuleType.CODE_PYTHON.value] = self.generate_python_code(finding)
        rules[RuleType.CODE_POWERSHELL.value] = self.generate_powershell_code(finding)
        rules[RuleType.CODE_BASH.value] = self.generate_bash_code(finding)
        
        return rules
    
    def generate_sigma_rule(self, finding: Dict) -> str:
        """Generate Sigma rule"""
        rule = {
            'title': f"Detection for {finding.get('name', 'Unknown Attack')}",
            'id': self.generate_rule_id(),
            'status': 'experimental',
            'description': f"Detects {finding.get('name', '')} activity",
            'references': ['https://attack.mitre.org/techniques/' + finding.get('technique_id', 'T1203')],
            'tags': ['attack.' + finding.get('technique_id', 'T1203').lower()],
            'author': 'AEGIS-ADAPT',
            'date': datetime.datetime.now().strftime('%Y-%m-%d'),
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': self.extract_indicators(finding.get('command', ''))
                },
                'condition': 'selection'
            },
            'falsepositives': ['Unknown'],
            'level': 'high'
        }
        
        return yaml.dump(rule, default_flow_style=False)
    
    def generate_yara_rule(self, finding: Dict) -> str:
        """Generate YARA rule"""
        indicators = self.extract_indicators(finding.get('output', ''))
        
        rule = f"""
rule aegis_adapt_{finding.get('technique_id', 'T1203').lower()} {{
    meta:
        description = "Detects {finding.get('name', 'Unknown Attack')}"
        author = "AEGIS-ADAPT"
        date = "{datetime.datetime.now().strftime('%Y-%m-%d')}"
        mitre_technique = "{finding.get('technique_id', 'T1203')}"
    
    strings:
        $s1 = "{indicators[0] if indicators else 'malicious'}" nocase
        
    condition:
        any of them
}}
"""
        return rule
    
    def generate_suricata_rule(self, finding: Dict) -> str:
        """Generate Suricata rule"""
        return f"""
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"AEGIS-ADAPT: {finding.get('name', 'Suspicious Activity')}";
    flow:established,to_server;
    content:"{self.extract_indicators(finding.get('command', ''))[0] if self.extract_indicators(finding.get('command', '')) else 'malicious'}";
    classtype:attempted-recon;
    sid:{random.randint(1000000, 9999999)};
    rev:1;
    priority:2;
)
"""
    
    def generate_splunk_query(self, finding: Dict) -> str:
        """Generate Splunk SPL query"""
        indicators = self.extract_indicators(finding.get('command', ''))
        query = f"""
index=main sourcetype=WinEventLog:Security
| search {" OR ".join([f'CommandLine="{ind}"' for ind in indicators])}
| stats count by host, user, CommandLine
| where count > 0
"""
        return query.strip()
    
    def generate_elastic_query(self, finding: Dict) -> str:
        """Generate Elasticsearch DSL query"""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"process.command_line": ind}}
                        for ind in self.extract_indicators(finding.get('command', ''))
                    ]
                }
            }
        }
        return json.dumps(query, indent=2)
    
    def generate_wazuh_rule(self, finding: Dict) -> str:
        """Generate Wazuh rule"""
        return f"""
<group name="aegis-adapt,">
  <rule id="{random.randint(100000, 999999)}" level="12">
    <if_sid>5716</if_sid>
    <match>{self.extract_indicators(finding.get('command', ''))[0] if self.extract_indicators(finding.get('command', '')) else 'malicious'}</match>
    <description>AEGIS-ADAPT: {finding.get('name', 'Suspicious Activity')}</description>
    <mitre>
      <id>{finding.get('technique_id', 'T1203')}</id>
    </mitre>
    <group>aegis_adapt_detection,</group>
  </rule>
</group>
"""
    
    def generate_modsecurity_rule(self, finding: Dict) -> str:
        """Generate ModSecurity WAF rule"""
        indicators = self.extract_indicators(finding.get('command', ''))
        return f"""
SecRule REQUEST_URI|ARGS|REQUEST_BODY "@contains {' || '.join(indicators)}" \\
    "id:{random.randint(1000000, 9999999)}", \\
    "phase:2", \\
    "deny", \\
    "status:403", \\
    "msg:'AEGIS-ADAPT: {finding.get('name', 'Suspicious Activity')}'", \\
    "tag:'{finding.get('technique_id', 'T1203')}'"
"""
    
    def generate_python_code(self, finding: Dict) -> str:
        """Generate Python remediation code"""
        return f"""
import os
import sys
import logging

def remediate_{finding.get('technique_id', 'T1203').lower()}():
    '''
    Remediation for {finding.get('name', 'Unknown Attack')}
    MITRE Technique: {finding.get('technique_id', 'T1203')}
    '''
    try:
        logging.info("Starting remediation for {finding.get('name', 'Unknown Attack')}")
        
        # Add your remediation logic here
        # Example: Block IP, kill process, remove file
        
        logging.info("Remediation completed successfully")
        return True
        
    except Exception as e:
        logging.error(f"Remediation failed: {{e}}")
        return False

if __name__ == "__main__":
    remediate_{finding.get('technique_id', 'T1203').lower()}()
"""
    
    def generate_powershell_code(self, finding: Dict) -> str:
        """Generate PowerShell remediation code"""
        return f"""
function Remediate-{finding.get('technique_id', 'T1203').replace('T', 'T')} {{
    <#
    .SYNOPSIS
        Remediation for {finding.get('name', 'Unknown Attack')}
    .DESCRIPTION
        MITRE Technique: {finding.get('technique_id', 'T1203')}
    #>
    
    Write-Host "Starting remediation for {finding.get('name', 'Unknown Attack')}"
    
    # Add your remediation logic here
    # Example: Block IP, kill process, remove file
    
    Write-Host "Remediation completed successfully"
}}
"""
    
    def generate_bash_code(self, finding: Dict) -> str:
        """Generate Bash remediation code"""
        return f"""#!/bin/bash
# Remediation for {finding.get('name', 'Unknown Attack')}
# MITRE Technique: {finding.get('technique_id', 'T1203')}

echo "Starting remediation for {finding.get('name', 'Unknown Attack')}"

# Add your remediation logic here
# Example: Block IP, kill process, remove file

echo "Remediation completed successfully"
"""
    
    def generate_rule_id(self) -> str:
        """Generate a unique rule ID"""
        return str(hashlib.md5(str(time.time()).encode()).hexdigest())[:8]
    
    def extract_indicators(self, text: str) -> List[str]:
        """Extract indicators from text for rule generation"""
        # Simplified indicator extraction
        words = text.split()
        indicators = []
        
        for word in words[:5]:  # Take first 5 words
            if len(word) > 3 and not word.isspace():
                indicators.append(word)
        
        return indicators
    
    def analyze_coverage_gaps(self) -> List[Dict]:
        """Analyze coverage gaps in existing defenses"""
        gaps = []
        
        try:
            # Get all attacks from database
            attacks = self.db.execute_query("SELECT * FROM attacks")
            
            # Get existing rules
            rules = self.db.execute_query("SELECT * FROM rules")
            
            if not attacks:
                return gaps
            
            # Group attacks by technique
            technique_attacks = {}
            for attack in attacks:
                tech_id = attack.get('technique_id', 'unknown')
                if tech_id not in technique_attacks:
                    technique_attacks[tech_id] = []
                technique_attacks[tech_id].append(attack)
            
            # Check coverage for each technique
            for tech_id, tech_attacks in technique_attacks.items():
                # Find rules for this technique
                tech_rules = [r for r in (rules or []) if r.get('rule_content', '').find(tech_id) > 0]
                
                coverage_score = len(tech_rules) / max(len(tech_attacks), 1)
                
                if coverage_score < self.config.DETECTION_THRESHOLD:
                    gaps.append({
                        'technique_id': tech_id,
                        'attacks_count': len(tech_attacks),
                        'rules_count': len(tech_rules),
                        'coverage_score': coverage_score,
                        'gap_size': self.config.DETECTION_THRESHOLD - coverage_score
                    })
            
            # Update coverage table
            for gap in gaps:
                self.db.execute_query(
                    "INSERT OR REPLACE INTO coverage (technique_id, detection_count, last_tested, coverage_score) VALUES (?, ?, ?, ?)",
                    (gap['technique_id'], gap['rules_count'], datetime.datetime.now().isoformat(), gap['coverage_score'])
                )
            
        except Exception as e:
            logger.error(f"Coverage gap analysis error: {e}")
        
        return gaps

# Blue Team Engine
class BlueTeamEngine:
    def __init__(self, config: Config, db_manager: DatabaseManager):
        self.config = config
        self.db = db_manager
    
    def deploy_rules(self, rules: Dict[str, str]) -> bool:
        """Simulate rule deployment to test environment"""
        try:
            # Create test environment directories
            os.makedirs('rules/deployed', exist_ok=True)
            os.makedirs('tests/results', exist_ok=True)
            
            # Save rules to files
            for rule_type, rule_content in rules.items():
                file_extension = {
                    'sigma': 'yml',
                    'yara': 'yar',
                    'suricata': 'rules',
                    'splunk': 'spl',
                    'elastic': 'json',
                    'wazuh': 'xml',
                    'modsecurity': 'conf',
                    'code_python': 'py',
                    'code_powershell': 'ps1',
                    'code_bash': 'sh'
                }.get(rule_type, 'txt')
                
                filename = f"rules/deployed/{rule_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}"
                with open(filename, 'w') as f:
                    f.write(rule_content)
            
            return True
            
        except Exception as e:
            logger.error(f"Rule deployment error: {e}")
            return False
    
    def simulate_detection(self, attack_command: str, rules: Dict[str, str]) -> Dict[str, bool]:
        """Simulate detection capabilities against attack"""
        detection_results = {}
        
        try:
            for rule_type, rule_content in rules.items():
                # Simple pattern matching simulation
                detected = False
                
                if rule_type in ['sigma', 'splunk', 'elastic']:
                    # Check if any indicator matches
                    indicators = self.extract_indicators_from_rule(rule_content)
                    detected = any(ind in attack_command for ind in indicators)
                
                elif rule_type == 'yara':
                    # Simple YARA simulation
                    detected = self.simulate_yara_match(rule_content, attack_command)
                
                elif rule_type == 'suricata':
                    # Simple Suricata simulation
                    detected = self.simulate_suricata_match(rule_content, attack_command)
                
                else:
                    # For other rule types, assume not detected in simulation
                    detected = False
                
                detection_results[rule_type] = detected
            
        except Exception as e:
            logger.error(f"Detection simulation error: {e}")
        
        return detection_results
    
    def extract_indicators_from_rule(self, rule_content: str) -> List[str]:
        """Extract indicators from rule content"""
        indicators = []
        
        # Try to extract from Sigma/YAML
        try:
            if rule_content.strip().startswith('title:'):
                rule_data = yaml.safe_load(rule_content)
                if 'detection' in rule_data:
                    # Extract from detection section (simplified)
                    detection_str = str(rule_data['detection'])
                    words = detection_str.split()
                    indicators.extend([w.strip('"\'') for w in words if len(w) > 3 and not w.isspace()][:5])
        except:
            pass
        
        # Generic extraction
        if not indicators:
            # Extract quoted strings
            indicators = re.findall(r'"([^"]*)"', rule_content)
            indicators.extend(re.findall(r"'([^']*)'", rule_content))
            
            # Take first 5 non-empty indicators
            indicators = [i for i in indicators if i and len(i) > 3][:5]
        
        return indicators
    
    def simulate_yara_match(self, rule_content: str, data: str) -> bool:
        """Simulate YARA rule matching"""
        # Simple string matching
        strings = re.findall(r'\$s\d+\s*=\s*"([^"]*)"', rule_content)
        return any(s in data for s in strings)
    
    def simulate_suricata_match(self, rule_content: str, data: str) -> bool:
        """Simulate Suricata rule matching"""
        # Extract content from rule
        content_match = re.search(r'content:"([^"]*)"', rule_content)
        if content_match:
            return content_match.group(1) in data
        return False
    
    def measure_effectiveness(self, attack_id: int, rules: Dict[str, str], variants: List[str]) -> Dict:
        """Measure rule effectiveness against attacks"""
        metrics = {
            'attacks_tested': len(variants),
            'detected': 0,
            'false_positives': 0,
            'detection_details': {}
        }
        
        try:
            for variant in variants:
                # Simulate detection
                detection_results = self.simulate_detection(variant, rules)
                
                # Check if any rule detected the variant
                detected = any(detection_results.values())
                
                if detected:
                    metrics['detected'] += 1
                
                metrics['detection_details'][variant[:50]] = detection_results
            
            # Calculate metrics
            if metrics['attacks_tested'] > 0:
                metrics['detection_rate'] = metrics['detected'] / metrics['attacks_tested']
                
                # Simulate false positives (simplified)
                metrics['false_positives'] = random.randint(0, max(1, int(metrics['attacks_tested'] * 0.1)))
                
                # Calculate precision, recall, F1
                tp = metrics['detected']
                fp = metrics['false_positives']
                fn = max(0, metrics['attacks_tested'] - tp)
                
                metrics['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
                metrics['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
                metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall']) if (metrics['precision'] + metrics['recall']) > 0 else 0
            
            # Store metrics in database
            rule_record = self.db.execute_query(
                "SELECT id FROM rules WHERE attack_id = ? ORDER BY version DESC LIMIT 1",
                (attack_id,)
            )
            
            if rule_record:
                self.db.update_metrics(rule_record[0]['id'], metrics)
            
        except Exception as e:
            logger.error(f"Effectiveness measurement error: {e}")
        
        return metrics
    
    def auto_tune_rules(self, rule_content: str, metrics: Dict) -> str:
        """Automatically tune rules based on metrics"""
        try:
            if metrics.get('detection_rate', 0) < self.config.DETECTION_THRESHOLD:
                # Enhance rule (simplified)
                if 'sigma' in rule_content or 'yaml' in rule_content:
                    # Add more indicators
                    rule_data = yaml.safe_load(rule_content)
                    if 'detection' in rule_data:
                        # Enhance detection (placeholder logic)
                        rule_data['detection']['enhanced'] = True
                    rule_content = yaml.dump(rule_data, default_flow_style=False)
                
                elif 'yara' in rule_content:
                    # Add more strings
                    rule_content += '\n        $s_extra = "malicious" nocase\n'
                
                elif 'suricata' in rule_content:
                    # Add more content matches
                    rule_content = rule_content.replace('msg:', 'content:"malicious"; msg:')
            
            return rule_content
            
        except Exception as e:
            logger.error(f"Auto-tune error: {e}")
            return rule_content

# Feedback Loop Controller
class FeedbackLoopController:
    def __init__(self, config: Config, db_manager: DatabaseManager, 
                 red_team: RedTeamEngine, analyzer: AnalyzerEngine, blue_team: BlueTeamEngine):
        self.config = config
        self.db = db_manager
        self.red_team = red_team
        self.analyzer = analyzer
        self.blue_team = blue_team
    
    def generate_attack_variants(self, attack_command: str, count: int = 10) -> List[str]:
        """Generate variants of an attack using different encodings and obfuscations"""
        variants = []
        
        encoding_methods = [
            ('base64', self.base64_encode),
            ('url', self.url_encode),
            ('utf16', self.utf16_encode),
            ('reverse', self.reverse_string),
            ('rot13', self.rot13_encode),
            ('hex', self.hex_encode),
            ('xor', self.xor_obfuscate),
            ('case', self.case_obfuscate),
            ('whitespace', self.whitespace_obfuscate),
            ('comment', self.comment_obfuscate)
        ]
        
        for method_name, method_func in encoding_methods[:count]:
            try:
                variant = method_func(attack_command)
                variants.append(variant)
                
                # Store variant in database
                self.db.execute_query(
                    "INSERT INTO variants (attack_id, variant_command, encoding) VALUES (?, ?, ?)",
                    (0, variant, method_name)  # attack_id 0 for generic
                )
                
            except Exception as e:
                logger.error(f"Variant generation error for {method_name}: {e}")
        
        return variants
    
    def base64_encode(self, command: str) -> str:
        """Base64 encode the command"""
        encoded = base64.b64encode(command.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"
    
    def url_encode(self, command: str) -> str:
        """URL encode the command"""
        return urllib.parse.quote(command)
    
    def utf16_encode(self, command: str) -> str:
        """UTF-16 encode the command"""
        encoded = command.encode('utf-16').hex()
        return f"python -c 'exec({encoded}.decode(\"hex\").decode(\"utf-16\"))'"
    
    def reverse_string(self, command: str) -> str:
        """Reverse the command string"""
        return command[::-1]
    
    def rot13_encode(self, command: str) -> str:
        """ROT13 encode the command"""
        return command.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))
    
    def hex_encode(self, command: str) -> str:
        """Hex encode the command"""
        return command.encode().hex()
    
    def xor_obfuscate(self, command: str) -> str:
        """XOR obfuscation with key 0xAA"""
        key = 0xAA
        encoded = ''.join(chr(ord(c) ^ key) for c in command)
        return f"python -c 'exec(\"\"\"{encoded}\"\"\")'"
    
    def case_obfuscate(self, command: str) -> str:
        """Random case obfuscation"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in command)
    
    def whitespace_obfuscate(self, command: str) -> str:
        """Add random whitespace"""
        words = command.split()
        return '  '.join(words)  # Double spaces
    
    def comment_obfuscate(self, command: str) -> str:
        """Add comments to obfuscate"""
        comment = f"# {''.join(random.choices(string.ascii_letters, k=10))}\n"
        return comment + command
    
    def run_feedback_loop(self, attack_id: int, attack_command: str, initial_rules: Dict[str, str]) -> Dict:
        """Run the complete feedback loop for an attack"""
        results = {
            'attack_id': attack_id,
            'initial_detection_rate': 0,
            'final_detection_rate': 0,
            'iterations': 0,
            'variants_tested': 0,
            'rules_evolution': []
        }
        
        try:
            current_rules = initial_rules.copy()
            iteration = 0
            detection_rate = 0
            
            while detection_rate < self.config.DETECTION_THRESHOLD and iteration < 5:
                iteration += 1
                
                # Generate variants
                variants = self.generate_attack_variants(attack_command, self.config.VARIANT_COUNT)
                
                # Test current rules
                metrics = self.blue_team.measure_effectiveness(attack_id, current_rules, variants)
                detection_rate = metrics.get('detection_rate', 0)
                
                # Store iteration results
                results['variants_tested'] += len(variants)
                results['rules_evolution'].append({
                    'iteration': iteration,
                    'detection_rate': detection_rate,
                    'metrics': metrics
                })
                
                if detection_rate < self.config.DETECTION_THRESHOLD:
                    # Tune rules for missed variants
                    for rule_type, rule_content in current_rules.items():
                        tuned_rule = self.blue_team.auto_tune_rules(rule_content, metrics)
                        current_rules[rule_type] = tuned_rule
                    
                    # Update rule in database
                    self.db.execute_query(
                        "UPDATE rules SET rule_content = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE attack_id = ?",
                        (json.dumps(current_rules), attack_id)
                    )
            
            results['final_detection_rate'] = detection_rate
            results['iterations'] = iteration
            
        except Exception as e:
            logger.error(f"Feedback loop error: {e}")
        
        return results

# Output Generators
class OutputGenerator:
    def __init__(self, config: Config, db_manager: DatabaseManager):
        self.config = config
        self.db = db_manager
    

    def generate_html_report(self, findings: List[Dict]) -> str:
        """Generate a simple HTML report"""
        try:
            # Calculate metrics
            total_attacks = len(findings)
            covered_attacks = sum(1 for f in findings if f.get('status') == 'detected')
            coverage_percentage = (covered_attacks / max(total_attacks, 1)) * 100
            
            # Build HTML as simple string concatenation (avoiding template issues)
            html = []
            html.append('<!DOCTYPE html>')
            html.append('<html>')
            html.append('<head>')
            html.append('    <title>AEGIS-ADAPT Security Report</title>')
            html.append('    <style>')
            html.append('        body { margin: 20px; font-family: Arial; }')
            html.append('        h1 { color: #333; border-bottom: 2px solid green; }')
            html.append('        h2 { color: #666; }')
            html.append('        table { border-collapse: collapse; width: 100%; }')
            html.append('        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }')
            html.append('        th { background-color: #4CAF50; color: white; }')
            html.append('        tr:nth-child(even) { background-color: #f2f2f2; }')
            html.append('        .heatmap { display: grid; grid-template-columns: repeat(8, 1fr); gap: 10px; margin: 20px 0; }')
            html.append('        .heatmap-cell { padding: 20px; text-align: center; color: white; border-radius: 5px; }')
            html.append('        .metric { display: inline-block; margin: 20px; padding: 20px; background: #f9f9f9; border-radius: 5px; }')
            html.append('    </style>')
            html.append('</head>')
            html.append('<body>')
            html.append(f'    <h1>AEGIS-ADAPT Security Report</h1>')
            html.append(f'    <p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
            
            # Executive Summary
            html.append('    <h2>Executive Summary</h2>')
            html.append('    <div class="metric">')
            html.append(f'        <h3>Total Attacks</h3>')
            html.append(f'        <p>{total_attacks}</p>')
            html.append('    </div>')
            html.append('    <div class="metric">')
            html.append(f'        <h3>Detection Coverage</h3>')
            html.append(f'        <p>{coverage_percentage:.1f}%</p>')
            html.append('    </div>')
            
            # Heatmap
            html.append('    <h2>MITRE ATT&CK Heatmap</h2>')
            html.append('    <div class="heatmap">')
            phases = ['Recon', 'Scan', 'Exploit', 'PrivEsc', 'Persist', 'Lateral', 'Evasion', 'Exfil']
            for phase in phases:
                color = f'rgba(255, 99, 71, {random.random()})'
                html.append(f'        <div class="heatmap-cell" style="background-color: {color};">{phase}</div>')
            html.append('    </div>')
            
            # Findings table
            html.append('    <h2>Findings Details</h2>')
            html.append('    <table>')
            html.append('        <tr><th>Name</th><th>Phase</th><th>Technique ID</th><th>Status</th><th>Timestamp</th></tr>')
            for finding in findings:
                html.append('        <tr>')
                html.append(f'            <td>{finding.get("name", "Unknown")}</td>')
                html.append(f'            <td>{finding.get("phase", "Unknown")}</td>')
                html.append(f'            <td>{finding.get("technique_id", "Unknown")}</td>')
                html.append(f'            <td>{finding.get("status", "Unknown")}</td>')
                html.append(f'            <td>{finding.get("timestamp", "Unknown")}</td>')
                html.append('        </tr>')
            html.append('    </table>')
            
            # Coverage gaps
            gaps = self.db.execute_query("SELECT * FROM coverage WHERE coverage_score < ?", (self.config.DETECTION_THRESHOLD,))
            if gaps:
                html.append('    <h2>Coverage Gaps</h2>')
                html.append('    <table>')
                html.append('        <tr><th>Technique ID</th><th>Gap Size</th><th>Priority</th></tr>')
                for gap in gaps:
                    gap_size = self.config.DETECTION_THRESHOLD - gap.get("coverage_score", 0)
                    if gap_size > 0.3:
                        priority = "High"
                    elif gap_size > 0.1:
                        priority = "Medium"
                    else:
                        priority = "Low"
                    html.append('        <tr>')
                    html.append(f'            <td>{gap.get("technique_id", "Unknown")}</td>')
                    html.append(f'            <td>{gap_size:.2f}</td>')
                    html.append(f'            <td>{priority}</td>')
                    html.append('        </tr>')
                html.append('    </table>')
            
            # Footer
            html.append('    <div style="margin-top: 50px; color: #999; font-size: 12px; text-align: center; border-top: 1px solid #ddd; padding-top: 20px;">')
            html.append('        <p>Report generated by AEGIS-ADAPT - Autonomous Defense & Adversarial Posture Tester</p>')
            html.append('        <p>Copyright (c) 2026 Ojas Satardekar</p>')
            html.append('    </div>')
            
            html.append('</body>')
            html.append('</html>')
            
            return '\n'.join(html)
            
        except Exception as e:
            logger.error(f"HTML generation error: {e}")
            return f"<html><body><h1>Error</h1><p>{e}</p></body></html>"
    def generate_json_export(self, data: List[Dict]) -> str:
        """Generate JSON export"""
        return json.dumps(data, indent=2, default=str)
    
    def generate_csv_export(self, data: List[Dict]) -> str:
        """Generate CSV export"""
        if not data:
            return ""
        
        df = pd.DataFrame(data)
        return df.to_csv(index=False)
    
    def generate_executive_summary(self, findings: List[Dict]) -> str:
        """Generate executive summary using LLM"""
        total_attacks = len(findings)
        successful_attacks = sum(1 for f in findings if f.get('status') == 'success')
        detected_attacks = sum(1 for f in findings if f.get('status') == 'detected')
        
        summary = f"""
AEGIS-ADAPT EXECUTIVE SUMMARY
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERVIEW
--------
Total Attacks Simulated: {total_attacks}
Successful Attacks: {successful_attacks}
Detected Attacks: {detected_attacks}
Detection Rate: {(detected_attacks/max(total_attacks,1))*100:.1f}%

KEY FINDINGS
------------
1. Most prevalent attack phases: {', '.join(set(f.get('phase', 'unknown') for f in findings))}
2. Top MITRE techniques observed: {', '.join(set(f.get('technique_id', 'unknown') for f in findings)[:5])}

RECOMMENDATIONS
---------------
1. Prioritize remediation for techniques with low detection coverage
2. Update detection rules for variants that bypassed current defenses
3. Conduct additional testing in high-risk areas

This report provides a high-level overview of the security posture assessment.
Detailed technical findings are available in the accompanying reports.
"""
        return summary

# Monitor Mode
class MonitorMode:
    def __init__(self, config: Config, db_manager: DatabaseManager,
                 red_team: RedTeamEngine, analyzer: AnalyzerEngine,
                 blue_team: BlueTeamEngine, feedback_loop: FeedbackLoopController,
                 output_gen: OutputGenerator):
        self.config = config
        self.db = db_manager
        self.red_team = red_team
        self.analyzer = analyzer
        self.blue_team = blue_team
        self.feedback_loop = feedback_loop
        self.output_gen = output_gen
        self.running = False
        self.monitor_thread = None
    
    def start(self, target: str):
        """Start continuous monitoring mode"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(target,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info(f"Monitor mode started for target: {target}")
    
    def stop(self):
        """Stop monitoring mode"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        logger.info("Monitor mode stopped")
    
    def _monitor_loop(self, target: str):
        """Main monitoring loop"""
        while self.running:
            try:
                # Step 1: Scan
                logger.info("Starting scan cycle")
                findings = self.red_team.scan_target(target)
                
                if findings:
                    # Step 2: Analyze
                    logger.info("Analyzing findings")
                    for finding in findings:
                        finding['technique_id'] = self.analyzer.map_to_mitre(finding)
                        rules = self.analyzer.generate_detection_rules(finding)
                        
                        # Store rules
                        attack_id = self.db.insert_attack(finding)
                        for rule_type, rule_content in rules.items():
                            self.db.execute_query(
                                "INSERT INTO rules (attack_id, rule_type, rule_content) VALUES (?, ?, ?)",
                                (attack_id, rule_type, rule_content)
                            )
                        
                        # Step 3: Test
                        logger.info(f"Testing rules for attack {attack_id}")
                        variants = self.feedback_loop.generate_attack_variants(
                            finding.get('command', ''), 
                            self.config.VARIANT_COUNT
                        )
                        
                        metrics = self.blue_team.measure_effectiveness(attack_id, rules, variants)
                        
                        # Step 4: Tune if needed
                        if metrics.get('detection_rate', 0) < self.config.DETECTION_THRESHOLD:
                            logger.info(f"Tuning rules for attack {attack_id}")
                            self.feedback_loop.run_feedback_loop(attack_id, finding.get('command', ''), rules)
                        
                        # Step 5: Check coverage gaps
                        gaps = self.analyzer.analyze_coverage_gaps()
                        if gaps:
                            logger.warning(f"Coverage gaps detected: {len(gaps)}")
                            
                            # Generate alert
                            self._send_alert(gaps)
                
                # Wait for next cycle
                logger.info(f"Monitor cycle complete. Waiting {self.config.UPDATE_INTERVAL} seconds")
                time.sleep(self.config.UPDATE_INTERVAL)
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _send_alert(self, gaps: List[Dict]):
        """Send alert for coverage gaps"""
        alert_message = f"""
ALERT: Coverage Gaps Detected
Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Number of Gaps: {len(gaps)}
Top Gap: {gaps[0]['technique_id'] if gaps else 'None'} - Gap Size: {gaps[0]['gap_size']:.2f}
"""
        logger.warning(alert_message)
        
        # Log to database
        self.db.execute_query(
            "INSERT INTO system_logs (component, level, message) VALUES (?, ?, ?)",
            ('MonitorMode', 'WARNING', alert_message)
        )

# Interactive Command Line Interface
class CommandLineInterface:
    def __init__(self):
        self.config = Config()
        self.db_manager = None
        self.rag_manager = None
        self.llm_manager = None
        self.red_team = None
        self.analyzer = None
        self.blue_team = None
        self.feedback_loop = None
        self.output_gen = None
        self.monitor = None
        self.setup_logging()
        self.initialize_components()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logger.remove()  # Remove default handler
        
        # Console logging
        logger.add(
            sys.stdout,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> - <level>{message}</level>",
            level=self.config.LOG_LEVEL
        )
        
        # File logging with rotation
        logger.add(
            "logs/aegis_adapt_{time}.log",
            rotation="10 MB",
            retention="30 days",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name} - {message}",
            level="DEBUG"
        )
    
    def initialize_components(self):
        """Initialize all system components"""
        try:
            # Create necessary directories
            os.makedirs('logs', exist_ok=True)
            os.makedirs('data', exist_ok=True)
            os.makedirs('rules', exist_ok=True)
            os.makedirs('output', exist_ok=True)
            os.makedirs('tests', exist_ok=True)
            
            # Initialize database
            self.db_manager = DatabaseManager(self.config.DATABASE_PATH)
            
            # Initialize RAG
            self.rag_manager = RAGManager(self.config)
            
            # Initialize LLM
            self.llm_manager = LLMManager(self.config)
            
            # Initialize engines
            self.red_team = RedTeamEngine(self.config, self.db_manager, self.rag_manager, self.llm_manager)
            self.analyzer = AnalyzerEngine(self.config, self.db_manager, self.llm_manager)
            self.blue_team = BlueTeamEngine(self.config, self.db_manager)
            self.feedback_loop = FeedbackLoopController(self.config, self.db_manager, 
                                                       self.red_team, self.analyzer, self.blue_team)
            self.output_gen = OutputGenerator(self.config, self.db_manager)
            self.monitor = MonitorMode(self.config, self.db_manager, self.red_team,
                                      self.analyzer, self.blue_team, self.feedback_loop, self.output_gen)
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Initialization error: {e}")
            sys.exit(1)
    
    def run(self):
        """Main CLI loop"""
        print("\n" + "="*60)
        print("AEGIS-ADAPT v1.0 - Autonomous Defense & Adversarial Posture Tester")
        print("Copyright (c) 2026 Ojas Satardekar")
        print("="*60)
        print("\nType 'help' for available commands\n")
        
        while True:
            try:
                command = input("aegis-adapt> ").strip().lower()
                
                if command == 'exit':
                    self.cleanup()
                    print("Exiting AEGIS-ADAPT")
                    break
                
                elif command == 'help':
                    self.show_help()
                
                elif command.startswith('scan '):
                    target = command[5:].strip()
                    self.cmd_scan(target)
                
                elif command == 'analyze':
                    self.cmd_analyze()
                
                elif command == 'test':
                    self.cmd_test()
                
                elif command == 'tune':
                    self.cmd_tune()
                
                elif command == 'heatmap':
                    self.cmd_heatmap()
                
                elif command.startswith('export '):
                    format_type = command[7:].strip()
                    self.cmd_export(format_type)
                
                elif command.startswith('monitor '):
                    target = command[8:].strip()
                    self.cmd_monitor(target)
                
                elif command == 'monitor stop':
                    self.cmd_monitor_stop()
                
                elif command == 'status':
                    self.cmd_status()
                
                elif command == 'history':
                    self.cmd_history()
                
                elif command == 'config':
                    self.cmd_config()
                
                elif command == '':
                    continue
                
                else:
                    print(f"Unknown command: {command}")
                    print("Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                print("\nInterrupted by user")
                self.cleanup()
                break
            
            except Exception as e:
                logger.error(f"Command error: {e}")
                print(f"Error: {e}")
    
    def run_command(self, command: str):
        """Run a single command and exit (for command-line arguments)"""
        try:
            if command.startswith('scan '):
                target = command[5:].strip()
                self.cmd_scan(target)
            elif command == 'analyze':
                self.cmd_analyze()
            elif command == 'test':
                self.cmd_test()
            elif command == 'tune':
                self.cmd_tune()
            elif command == 'heatmap':
                self.cmd_heatmap()
            elif command.startswith('export '):
                format_type = command[7:].strip()
                self.cmd_export(format_type)
            elif command.startswith('monitor '):
                target = command[8:].strip()
                self.cmd_monitor(target)
            else:
                print(f"Unknown command: {command}")
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            print(f"Error: {e}")
    
    def show_help(self):
        """Show help information"""
        help_text = """
AVAILABLE COMMANDS:
-------------------
scan <target>           - Run reconnaissance and find vulnerabilities
analyze                 - Map findings to MITRE and generate initial rules
test                    - Launch attack variants against generated rules
tune                    - Auto-improve rules based on test results
heatmap                 - Show MITRE ATT&CK coverage visualization
export <format>         - Export rules or reports (sigma, yara, splunk, elastic, html, json, csv)
monitor <target>        - Start continuous mode (scan, analyze, test, tune loop)
monitor stop            - Stop continuous monitoring
status                  - Show current system status and metrics
history                 - Show past scan results
config                  - Display current configuration
exit                    - Quit the application
help                    - Show this help message
"""
        print(help_text)
    
    def cmd_scan(self, target: str):
        """Execute scan command"""
        print(f"\n[+] Starting scan on target: {target}")
        
        try:
            findings = self.red_team.scan_target(target)
            
            print(f"\n[+] Scan completed. Found {len(findings)} findings:\n")
            
            for i, finding in enumerate(findings, 1):
                print(f"  {i}. {finding.get('name', 'Unknown')}")
                print(f"     Phase: {finding.get('phase', 'Unknown')}")
                print(f"     Status: {finding.get('status', 'Unknown')}")
                print()
            
            # Save to database
            for finding in findings:
                self.db_manager.insert_attack(finding)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            print(f"[-] Scan failed: {e}")
    
    def cmd_analyze(self):
        """Execute analyze command"""
        print("\n[+] Analyzing findings and generating rules...")
        
        try:
            # Get latest attacks
            attacks = self.db_manager.execute_query(
                "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10"
            )
            
            if not attacks:
                print("[-] No attacks found to analyze")
                return
            
            for attack in attacks:
                print(f"\n[+] Analyzing attack: {attack.get('name', 'Unknown')}")
                
                # Map to MITRE
                technique_id = self.analyzer.map_to_mitre(attack)
                print(f"    MITRE Technique: {technique_id}")
                
                # Generate rules
                rules = self.analyzer.generate_detection_rules(attack)
                
                # Save rules to database
                for rule_type, rule_content in rules.items():
                    self.db_manager.execute_query(
                        "INSERT INTO rules (attack_id, rule_type, rule_content) VALUES (?, ?, ?)",
                        (attack['id'], rule_type, rule_content)
                    )
                
                print(f"    Generated {len(rules)} detection rules")
                
                # Deploy rules (simulate)
                self.blue_team.deploy_rules(rules)
            
            # Check coverage gaps
            gaps = self.analyzer.analyze_coverage_gaps()
            if gaps:
                print(f"\n[!] Detected {len(gaps)} coverage gaps")
                for gap in gaps[:5]:
                    print(f"    {gap['technique_id']}: {gap['gap_size']:.2f} gap")
            
            print("\n[+] Analysis complete")
            
        except Exception as e:
            logger.error(f"Analyze error: {e}")
            print(f"[-] Analysis failed: {e}")
    
    def cmd_test(self):
        """Execute test command"""
        print("\n[+] Testing rules against attack variants...")
        
        try:
            # Get latest rules
            rules_data = self.db_manager.execute_query(
                "SELECT * FROM rules ORDER BY created_at DESC LIMIT 5"
            )
            
            if not rules_data:
                print("[-] No rules found to test")
                return
            
            # Group rules by attack
            rules_by_attack = {}
            for rule in rules_data:
                attack_id = rule['attack_id']
                if attack_id not in rules_by_attack:
                    rules_by_attack[attack_id] = {}
                rules_by_attack[attack_id][rule['rule_type']] = rule['rule_content']
            
            for attack_id, rules in rules_by_attack.items():
                print(f"\n[+] Testing rules for attack ID: {attack_id}")
                
                # Get original attack
                attack = self.db_manager.execute_query(
                    "SELECT * FROM attacks WHERE id = ?", (attack_id,)
                )
                
                if not attack:
                    continue
                
                attack_command = attack[0].get('command', '')
                
                # Generate variants
                variants = self.feedback_loop.generate_attack_variants(
                    attack_command, self.config.VARIANT_COUNT
                )
                
                print(f"    Generated {len(variants)} variants")
                
                # Measure effectiveness
                metrics = self.blue_team.measure_effectiveness(attack_id, rules, variants)
                
                print(f"    Detection Rate: {metrics.get('detection_rate', 0)*100:.1f}%")
                print(f"    False Positives: {metrics.get('false_positives', 0)}")
                print(f"    F1 Score: {metrics.get('f1_score', 0):.3f}")
                
                if metrics.get('detection_rate', 0) < self.config.DETECTION_THRESHOLD:
                    print("    [!] Below threshold - tuning recommended")
            
            print("\n[+] Testing complete")
            
        except Exception as e:
            logger.error(f"Test error: {e}")
            print(f"[-] Testing failed: {e}")
    
    def cmd_tune(self):
        """Execute tune command"""
        print("\n[+] Tuning rules based on test results...")
        
        try:
            # Get underperforming rules
            metrics = self.db_manager.execute_query("""
                SELECT r.*, m.* FROM rules r
                JOIN metrics m ON r.id = m.rule_id
                WHERE m.detection_rate < ?
                ORDER BY m.test_date DESC
            """, (self.config.DETECTION_THRESHOLD,))
            
            if not metrics:
                print("[-] No underperforming rules found")
                return
            
            for metric in metrics:
                print(f"\n[+] Tuning rule ID: {metric['rule_id']}")
                print(f"    Current detection rate: {metric['detection_rate']*100:.1f}%")
                
                # Get attack details
                attack = self.db_manager.execute_query(
                    "SELECT * FROM attacks WHERE id = ?", (metric['attack_id'],)
                )
                
                if not attack:
                    continue
                
                # Run feedback loop
                results = self.feedback_loop.run_feedback_loop(
                    metric['attack_id'],
                    attack[0].get('command', ''),
                    {metric['rule_type']: metric['rule_content']}
                )
                
                print(f"    Iterations: {results.get('iterations', 0)}")
                print(f"    Final detection rate: {results.get('final_detection_rate', 0)*100:.1f}%")
            
            print("\n[+] Tuning complete")
            
        except Exception as e:
            logger.error(f"Tune error: {e}")
            print(f"[-] Tuning failed: {e}")
    
    def cmd_heatmap(self):
        """Show MITRE ATT&CK coverage heatmap"""
        print("\n[+] MITRE ATT&CK Coverage Heatmap")
        print("-" * 60)
        
        try:
            # Get coverage data
            coverage = self.db_manager.execute_query("""
                SELECT technique_id, coverage_score, detection_count, last_tested
                FROM coverage
                ORDER BY technique_id
            """)
            
            if not coverage:
                print("No coverage data available")
                return
            
            # Group by phase (simplified)
            phases = {
                'Recon': ['T1590', 'T1595', 'T1592'],
                'Scan': ['T1046', 'T1040'],
                'Exploit': ['T1203', 'T1210'],
                'PrivEsc': ['T1068', 'T1548'],
                'Persist': ['T1547', 'T1136'],
                'Lateral': ['T1021', 'T1080'],
                'Evasion': ['T1027', 'T1070'],
                'Exfil': ['T1041', 'T1048']
            }
            
            # Print heatmap
            print("\nCoverage Score (0.00 - 1.00):")
            print()
            
            for phase, techniques in phases.items():
                print(f"{phase:10}", end=" ")
                for tech in techniques:
                    tech_coverage = next((c['coverage_score'] for c in coverage if c['technique_id'] == tech), 0)
                    
                    # Color coding
                    if tech_coverage >= 0.9:
                        color = "GREEN"
                    elif tech_coverage >= 0.7:
                        color = "YELLOW"
                    elif tech_coverage >= 0.5:
                        color = "ORANGE"
                    else:
                        color = "RED"
                    
                    print(f" [{color:6}] ", end="")
                print()
            
            print("\nLegend: GREEN >=90%  YELLOW 70-89%  ORANGE 50-69%  RED <50%")
            print("-" * 60)
            
        except Exception as e:
            logger.error(f"Heatmap error: {e}")
            print(f"[-] Heatmap generation failed: {e}")
    
    def cmd_export(self, format_type: str):
        """Export data in specified format"""
        print(f"\n[+] Exporting data in {format_type} format...")
        
        try:
            # Get data to export
            attacks = self.db_manager.execute_query(
                "SELECT * FROM attacks ORDER BY timestamp DESC"
            )
            
            if not attacks:
                print("[-] No data to export")
                return
            
            filename = f"output/aegis_adapt_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            if format_type == 'html':
                content = self.output_gen.generate_html_report(attacks)
                filename += '.html'
            
            elif format_type == 'json':
                content = self.output_gen.generate_json_export(attacks)
                filename += '.json'
            
            elif format_type == 'csv':
                content = self.output_gen.generate_csv_export(attacks)
                filename += '.csv'
            
            elif format_type in ['sigma', 'yara', 'splunk', 'elastic']:
                # Export specific rule types
                rules = self.db_manager.execute_query(
                    "SELECT * FROM rules WHERE rule_type = ? ORDER BY created_at DESC",
                    (format_type,)
                )
                
                if not rules:
                    print(f"[-] No {format_type} rules found")
                    return
                
                content = '\n\n---\n\n'.join([r['rule_content'] for r in rules])
                filename += f'.{format_type}'
            
            else:
                print(f"[-] Unsupported format: {format_type}")
                return
            
            # Write to file
            with open(filename, 'w') as f:
                f.write(content)
            
            print(f"[+] Export saved to: {filename}")
            
        except Exception as e:
            logger.error(f"Export error: {e}")
            print(f"[-] Export failed: {e}")
    
    def cmd_monitor(self, target: str):
        """Start monitor mode"""
        if self.monitor.running:
            print("[-] Monitor mode is already running")
            return
        
        print(f"\n[+] Starting monitor mode for target: {target}")
        print("    Press Ctrl+C to stop monitoring\n")
        
        self.monitor.start(target)
    
    def cmd_monitor_stop(self):
        """Stop monitor mode"""
        if not self.monitor.running:
            print("[-] Monitor mode is not running")
            return
        
        self.monitor.stop()
        print("[+] Monitor mode stopped")
    
    def cmd_status(self):
        """Show system status"""
        print("\n[+] System Status")
        print("-" * 60)
        
        try:
            # Get counts
            attack_count = self.db_manager.execute_query("SELECT COUNT(*) as count FROM attacks")
            rule_count = self.db_manager.execute_query("SELECT COUNT(*) as count FROM rules")
            variant_count = self.db_manager.execute_query("SELECT COUNT(*) as count FROM variants")
            metric_count = self.db_manager.execute_query("SELECT COUNT(*) as count FROM metrics")
            
            # Get latest scan
            latest_scan = self.db_manager.execute_query(
                "SELECT timestamp FROM attacks ORDER BY timestamp DESC LIMIT 1"
            )
            
            # Get coverage stats
            coverage_avg = self.db_manager.execute_query(
                "SELECT AVG(coverage_score) as avg FROM coverage"
            )
            
            print(f"Monitor Mode: {'Running' if self.monitor.running else 'Stopped'}")
            print(f"Total Attacks: {attack_count[0]['count'] if attack_count else 0}")
            print(f"Total Rules: {rule_count[0]['count'] if rule_count else 0}")
            print(f"Total Variants: {variant_count[0]['count'] if variant_count else 0}")
            print(f"Total Metrics: {metric_count[0]['count'] if metric_count else 0}")
            print(f"Average Coverage: {coverage_avg[0]['avg']*100:.1f}%")
            print(f"Latest Scan: {latest_scan[0]['timestamp'] if latest_scan else 'Never'}")
            print(f"Detection Threshold: {self.config.DETECTION_THRESHOLD*100:.0f}%")
            print(f"Available Tools: {sum(self.red_team.tools.values())}/{len(self.red_team.tools)}")
            
            # Show tool availability
            available_tools = [t for t, available in self.red_team.tools.items() if available]
            if available_tools:
                print(f"\nAvailable Tools: {', '.join(available_tools[:10])}")
                if len(available_tools) > 10:
                    print(f"  ... and {len(available_tools) - 10} more")
            
            print("-" * 60)
            
        except Exception as e:
            logger.error(f"Status error: {e}")
            print(f"[-] Status check failed: {e}")
    
    def cmd_history(self):
        """Show scan history"""
        print("\n[+] Scan History")
        print("-" * 60)
        
        try:
            # Get recent attacks
            attacks = self.db_manager.execute_query("""
                SELECT id, name, phase, technique_id, timestamp, status
                FROM attacks
                ORDER BY timestamp DESC
                LIMIT 20
            """)
            
            if not attacks:
                print("No scan history available")
                return
            
            for attack in attacks:
                print(f"[{attack['timestamp']}] {attack['name']}")
                print(f"    Phase: {attack['phase']}, Technique: {attack['technique_id']}, Status: {attack['status']}")
                print()
            
            print("-" * 60)
            
        except Exception as e:
            logger.error(f"History error: {e}")
            print(f"[-] History retrieval failed: {e}")
    
    def cmd_config(self):
        """Display current configuration"""
        print("\n[+] Current Configuration")
        print("-" * 60)
        
        config_vars = {
            'DATASET_PATH': self.config.DATASET_PATH,
            'DATABASE_PATH': self.config.DATABASE_PATH,
            'CHROMA_PATH': self.config.CHROMA_PATH,
            'FAISS_INDEX_PATH': self.config.FAISS_INDEX_PATH,
            'OLLAMA_MODEL': self.config.OLLAMA_MODEL,
            'GEMINI_MODEL': self.config.GEMINI_MODEL,
            'MAX_WORKERS': self.config.MAX_WORKERS,
            'VARIANT_COUNT': self.config.VARIANT_COUNT,
            'DETECTION_THRESHOLD': f"{self.config.DETECTION_THRESHOLD*100:.0f}%",
            'UPDATE_INTERVAL': f"{self.config.UPDATE_INTERVAL} seconds",
            'LOG_LEVEL': self.config.LOG_LEVEL,
            'REQUEST_TIMEOUT': f"{self.config.REQUEST_TIMEOUT} seconds",
            'MAX_RETRIES': self.config.MAX_RETRIES
        }
        
        for key, value in config_vars.items():
            print(f"{key:20}: {value}")
        
        # Show API key status
        print(f"{'GEMINI_API_KEY':20}: {'Set' if self.config.GEMINI_API_KEY else 'Not Set'}")
        
        # Show component availability
        print(f"\nComponent Status:")
        print(f"  ChromaDB: {'Available' if CHROMA_AVAILABLE else 'Not Available'}")
        print(f"  FAISS: {'Available' if FAISS_AVAILABLE else 'Not Available'}")
        print(f"  Ollama: {'Available' if OLLAMA_AVAILABLE else 'Not Available'}")
        print(f"  Gemini: {'Available' if GEMINI_AVAILABLE and self.config.GEMINI_API_KEY else 'Not Available'}")
        
        print("-" * 60)
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up resources")
        
        # Stop monitor mode if running
        if self.monitor and self.monitor.running:
            self.monitor.stop()
        
        # Close database connections
        if self.db_manager:
            # SQLite connection will be closed automatically
            pass
        
        logger.info("Cleanup complete")

# Main entry point
def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AEGIS-ADAPT - Autonomous Defense & Adversarial Posture Tester')
    parser.add_argument('--target', '-t', help='Target to scan')
    parser.add_argument('--command', '-c', help='Execute single command and exit')
    parser.add_argument('--config', help='Path to custom .env file')
    
    args = parser.parse_args()
    
    # Load custom config if specified
    if args.config:
        load_dotenv(args.config)
    
    # Run CLI
    cli = CommandLineInterface()
    
    if args.command:
        # Execute single command
        cli.run_command(args.command)
    elif args.target:
        # Quick scan
        cli.cmd_scan(args.target)
    else:
        # Interactive mode
        cli.run()

if __name__ == "__main__":
    main()
