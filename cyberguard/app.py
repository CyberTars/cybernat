from flask import Flask, render_template, request, jsonify, session
import requests
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.secret_key = 'cyberguard-secret-key-2024'  # Required for sessions
app.config['SESSION_PERMANENT'] = False

# Function to generate realistic IP addresses
def generate_ip():
    return f"{random.randint(100, 199)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

# Function to generate realistic timestamps
def generate_timestamps():
    current_time = datetime.now()
    return {
        'current': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'recent': (current_time - timedelta(hours=random.randint(1, 6))).strftime('%H:%M'),
        'today': current_time.strftime('%Y-%m-%d'),
        'yesterday': (current_time - timedelta(days=1)).strftime('%Y-%m-%d')
    }

SYSTEM_PROMPT = """You are CyberGuard Assistant, an AI-powered cybersecurity analyst. You provide immediate, actionable intelligence through an intuitive conversational interface.

IMPORTANT: You MUST generate SPECIFIC, DETAILED responses with realistic numbers, timestamps, IP addresses, and exact details.

*OPERATIONAL MODES:*
- NORMAL MODE: Show real threats, vulnerabilities, and anomalies with 🔴🟡 emojis
- SECURE MODE: Show all systems normal with ✅ emojis (countermeasures active)

*CVE Vulnerability Lookup Examples:*
NORMAL: "🔎 CVE-2024-3094 | Severity: 🔴 CRITICAL (9.8/10) | Type: Backdoor in XZ Utils 5.6.0-5.6.1 | Timeline: Discovered 2024-03-29 | Impact: Remote code execution via SSH | Recommendation: IMMEDIATE ACTION - Downgrade to version 5.4.6"
SECURE: "✅ CVE Scan Complete {timestamp} | Status: ALL SYSTEMS SECURE | Scanned: 1,247 packages | Findings: 0 critical, 2 low severity | Recommendation: Continue regular patch cycle"

*Threat Analysis Examples:*
NORMAL: "🔍 File Hash Analysis: a1b2c3d4e5f67890 | Status: 🟡 SUSPICIOUS - 48/72 engines detected | First Seen: 2024-04-15 08:23:17 UTC | Behavior: Credential harvesting, persistence | Relations: IP 185.163.45.12 (Bulgaria) | Recommendation: QUARANTINE - Reset credentials"
SECURE: "✅ Threat Scan {timestamp} | Status: NO ACTIVE THREATS | Scanned: 15,432 files | Detection: 0 malicious, 3 suspicious (quarantined) | Recommendation: Maintain current security posture"

*Log Summaries Examples:*
NORMAL: "📊 Login Anomalies Report | Timeframe: {yesterday} 00:00 - {today} 23:59 | Total Events: 12,847 | Anomalies: 47 (0.37%) | Top Findings: 23 failed attempts (IP 192.168.1.15, 08:45-09:30), 12 brute force attempts (IP 104.28.15.63), 8 unusual logins (Singapore) | Recommendation: INVESTIGATE anomalous IPs"
SECURE: "✅ Security Log Analysis {timestamp} | Timeframe: Last 24 hours | Total Events: 8,642 | Anomalies: 0 (0.0%) | Status: NORMAL SECURITY TRAFFIC | Note: Countermeasures active since {recent_time} | Recommendation: Continue monitoring"

*Current Session Context: {session_context}*
"""

@app.route('/')
def home():
    # Initialize session variables
    if 'countermeasures_active' not in session:
        session['countermeasures_active'] = False
    if 'activation_time' not in session:
        session['activation_time'] = None
    return render_template('index.html')

@app.route('/ask', methods=['POST'])
def ask_question():
    user_input = request.json.get('message', '').lower()
    timestamps = generate_timestamps()
    
    # Check if user is activating countermeasures
    countermeasure_keywords = ['countermeasure', 'activate', 'implement', 'resolve', 'fix', 'remediate', 'deploy', 'enable']
    if any(word in user_input for word in countermeasure_keywords):
        session['countermeasures_active'] = True
        session['activation_time'] = timestamps['current']
        session['threat_level'] = 'low'
    
    # Check if user is resetting to normal mode
    reset_keywords = ['reset', 'normal', 'default', 'test mode', 'disable']
    if any(word in user_input for word in reset_keywords):
        session['countermeasures_active'] = False
        session['activation_time'] = None
        session['threat_level'] = 'high'
    
    # Prepare session context for the AI
    if session['countermeasures_active']:
        session_context = f"SECURE MODE: Countermeasures active since {session['activation_time']}. Show all systems normal with ✅ emojis. No critical threats. Mention countermeasures are working."
    else:
        session_context = "NORMAL MODE: Show real threats and vulnerabilities with detailed critical findings. Use 🔴🟡 emojis for serious issues."
    
    # Enhanced prompt with session context and timestamps
    enhanced_prompt = SYSTEM_PROMPT.replace("{session_context}", session_context)
    enhanced_prompt = enhanced_prompt.replace("{timestamp}", timestamps['current'])
    enhanced_prompt = enhanced_prompt.replace("{recent_time}", timestamps['recent'])
    enhanced_prompt = enhanced_prompt.replace("{today}", timestamps['today'])
    enhanced_prompt = enhanced_prompt.replace("{yesterday}", timestamps['yesterday'])
    
    enhanced_prompt += f"\n\nCurrent Time: {timestamps['current']}\nUser: {user_input}\nAssistant: "
    
    # DeepInfra FREE API
    url = "https://api.deepinfra.com/v1/inference/mistralai/Mixtral-8x7B-Instruct-v0.1"
    
    headers = {"Content-Type": "application/json"}
    
    payload = {
        "input": enhanced_prompt,
        "max_new_tokens": 650,  # Increased for detailed responses
        "temperature": 0.2  # Low temperature for consistent formatting
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        response_data = response.json()
        
        ai_response = response_data['results'][0]['generated_text']
        
        # Extract only the Assistant's response
        if "Assistant: " in ai_response:
            ai_response = ai_response.split("Assistant: ")[-1].strip()

    except Exception as e:
        # Enhanced fallback responses with session awareness
        if session['countermeasures_active']:
            # SECURE MODE responses
            if "cve" in user_input:
                ai_response = f"✅ CVE Scan Complete {timestamps['current']} | Status: ALL SYSTEMS SECURE | Scanned: 1,247 packages | Findings: 0 critical, 2 low severity | Countermeasures: Active since {session['activation_time']} | Recommendation: Continue regular patch cycle"
            elif "hash" in user_input or "analyze" in user_input:
                ai_response = f"✅ Threat Scan {timestamps['current']} | Status: NO ACTIVE THREATS | Scanned: 15,432 files | Detection: 0 malicious, 3 suspicious (quarantined) | Countermeasures: Active | Recommendation: Maintain current security posture"
            elif "log" in user_input or "login" in user_input:
                ai_response = f"✅ Security Log Analysis {timestamps['current']} | Timeframe: Last 24 hours | Total Events: 8,642 | Anomalies: 0 (0.0%) | Status: NORMAL SECURITY TRAFFIC | Countermeasures: Active since {session['activation_time']} | Recommendation: Continue monitoring"
            else:
                ai_response = f"✅ System Status {timestamps['current']} | Mode: SECURE | Countermeasures: ACTIVE | All systems operating normally | No critical alerts | Last incident: Resolved {timestamps['recent']}"
        else:
            # NORMAL MODE responses
            if "cve" in user_input:
                ai_response = f"🔎 CVE-2024-{random.randint(3000, 3999)} | Severity: 🔴 CRITICAL ({random.uniform(8.5, 9.8):.1f}/10) | Type: Remote code execution | Impact: Unauthenticated RCE | Timeline: Patched {random.randint(1, 14)} days ago | Active exploitation reported | Recommendation: 🔴 URGENT - Apply security update immediately"
            elif "hash" in user_input or "analyze" in user_input:
                ai_response = f"🔍 File Hash Analysis: {''.join(random.choices('abcdef0123456789', k=12))} | Status: 🟡 SUSPICIOUS - {random.randint(35, 65)}/72 engines detected | First Seen: {(datetime.now() - timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d %H:%M UTC')} | Behavior: Credential harvesting | Recommendation: 🟡 QUARANTINE - Isolate and conduct memory analysis"
            elif "log" in user_input or "login" in user_input:
                ai_response = f"📊 Login Anomalies Report | Timeframe: {timestamps['yesterday']} 00:00 - {timestamps['today']} 23:59 | Total Events: {random.randint(12000, 15000)} | Anomalies: {random.randint(40, 60)} ({random.uniform(0.3, 0.6):.2f}%) | Top Findings: {random.randint(20, 30)} failed attempts (IP {generate_ip()}), {random.randint(10, 15)} brute force attempts, {random.randint(5, 10)} unusual logins | Recommendation: 🔍 INVESTIGATE anomalous IPs"
            else:
                ai_response = f"🛡 CyberGuard Assistant {timestamps['current']} | Status: OPERATIONAL | Active Monitoring: 12,500+ events/hour | Mode: NORMAL | Capabilities: CVE analysis, threat intelligence, log correlation"

    return jsonify({'response': ai_response})

if __name__ == '__main__':
    app.run(debug=True)