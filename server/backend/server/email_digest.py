"""
server/email_digest.py — Daily Email Digest for EDR Alerts

Sends a smart daily summary email to security team:
- Critical/High/Medium alert counts
- Top threats detected
- Most targeted systems
- Statistics and trends
- Links to full reports

Configuration (environment variables):
    EDR_DIGEST_ENABLED=true
    EDR_DIGEST_TIME=08:00          # Send at 8am daily
    EDR_DIGEST_EMAILS=admin@company.com,soc@company.com
    EDR_SMTP_HOST=smtp.gmail.com
    EDR_SMTP_PORT=587
    EDR_SMTP_USER=edr@company.com
    EDR_SMTP_PASS=yourpassword
    EDR_SMTP_FROM=edr@company.com

Usage:
    from server.email_digest import start_digest_scheduler
    start_digest_scheduler()  # Call from server/__init__.py
"""

import os
import smtplib
import threading
import time
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter
from server.database.storage import _conn


# Configuration
ENABLED = os.environ.get("EDR_DIGEST_ENABLED", "false").lower() == "true"
SEND_TIME = os.environ.get("EDR_DIGEST_TIME", "08:00")  # HH:MM format
EMAILS = os.environ.get("EDR_DIGEST_EMAILS", "").split(",")
SMTP_HOST = os.environ.get("EDR_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("EDR_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("EDR_SMTP_USER", "")
SMTP_PASS = os.environ.get("EDR_SMTP_PASS", "")
SMTP_FROM = os.environ.get("EDR_SMTP_FROM", SMTP_USER)
SERVER_URL = os.environ.get("EDR_SERVER_URL", "http://localhost:5000")


def get_daily_stats():
    """Get statistics for last 24 hours"""
    conn = _conn()
    yesterday = int(time.time()) - 86400
    
    # Alert counts by severity
    alerts = conn.execute(
        "SELECT risk_level, COUNT(*) as count FROM alerts "
        "WHERE timestamp > ? GROUP BY risk_level",
        (yesterday,)
    ).fetchall()
    
    alert_counts = {row["risk_level"]: row["count"] for row in alerts}
    
    # Total events processed
    total_events = conn.execute(
        "SELECT COUNT(*) as count FROM events WHERE time > ?",
        (yesterday,)
    ).fetchone()["count"]
    
    # Top threats (by MITRE technique)
    top_threats = conn.execute(
        "SELECT technique, COUNT(*) as count FROM alerts "
        "WHERE timestamp > ? AND technique != '' "
        "GROUP BY technique ORDER BY count DESC LIMIT 5",
        (yesterday,)
    ).fetchall()
    
    # Most targeted systems
    top_systems = conn.execute(
        "SELECT system_id, COUNT(*) as count FROM alerts "
        "WHERE timestamp > ? "
        "GROUP BY system_id ORDER BY count DESC LIMIT 5",
        (yesterday,)
    ).fetchall()
    
    # False positives (suppressed alerts)
    false_positives = conn.execute(
        "SELECT COUNT(*) as count FROM suppressions "
        "WHERE created_at > ?",
        (yesterday,)
    ).fetchone()["count"]
    
    # Auto-responses
    auto_responses = conn.execute(
        "SELECT COUNT(*) as count FROM audit_log "
        "WHERE timestamp > ? AND action = 'auto_kill'",
        (yesterday,)
    ).fetchone()["count"]
    
    # Active incidents
    active_incidents = conn.execute(
        "SELECT COUNT(*) as count FROM incidents "
        "WHERE status = 'investigating'"
    ).fetchone()["count"]
    
    # Get yesterday's stats for comparison
    two_days_ago = yesterday - 86400
    yesterday_alerts = conn.execute(
        "SELECT COUNT(*) as count FROM alerts "
        "WHERE timestamp BETWEEN ? AND ?",
        (two_days_ago, yesterday)
    ).fetchone()["count"]
    
    return {
        "alert_counts": alert_counts,
        "total_events": total_events,
        "top_threats": top_threats,
        "top_systems": top_systems,
        "false_positives": false_positives,
        "auto_responses": auto_responses,
        "active_incidents": active_incidents,
        "yesterday_alerts": yesterday_alerts,
    }


def format_html_email(stats, date_str):
    """Generate HTML email body"""
    
    critical = stats["alert_counts"].get("CRITICAL", 0)
    high = stats["alert_counts"].get("HIGH", 0)
    medium = stats["alert_counts"].get("MEDIUM", 0)
    low = stats["alert_counts"].get("LOW", 0)
    total_alerts = critical + high + medium + low
    
    # Calculate trend
    yesterday_total = stats["yesterday_alerts"]
    if yesterday_total > 0:
        trend_pct = ((total_alerts - yesterday_total) / yesterday_total) * 100
        trend_icon = "↑" if trend_pct > 0 else "↓" if trend_pct < 0 else "→"
        trend_color = "#e74c3c" if trend_pct > 10 else "#27ae60" if trend_pct < -10 else "#95a5a6"
        trend_text = f'<span style="color: {trend_color};">{trend_icon} {abs(trend_pct):.1f}% vs. yesterday</span>'
    else:
        trend_text = '<span style="color: #95a5a6;">→ First day</span>'
    
    # Alert rate
    alert_rate = (total_alerts / stats["total_events"] * 100) if stats["total_events"] > 0 else 0
    
    # Top threats HTML
    threats_html = ""
    if stats["top_threats"]:
        for threat in stats["top_threats"]:
            threats_html += f'<li><strong>{threat["technique"]}</strong>: {threat["count"]} incidents</li>\n'
    else:
        threats_html = '<li style="color: #27ae60;">No threats detected</li>'
    
    # Top systems HTML
    systems_html = ""
    if stats["top_systems"]:
        for sys in stats["top_systems"]:
            systems_html += f'<li><strong>{sys["system_id"]}</strong>: {sys["count"]} alerts</li>\n'
    else:
        systems_html = '<li>No systems targeted</li>'
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .content {{ background: #fff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }}
        .stat-box.critical {{ border-left-color: #e74c3c; }}
        .stat-box.high {{ border-left-color: #e67e22; }}
        .stat-box.medium {{ border-left-color: #f39c12; }}
        .stat-box.low {{ border-left-color: #3498db; }}
        .stat-number {{ font-size: 32px; font-weight: bold; margin: 0; }}
        .stat-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .highlight {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0; border-radius: 4px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; color: #666; font-size: 14px; }}
        .btn {{ display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 4px; margin: 10px 5px; }}
        ul {{ padding-left: 20px; }}
        li {{ margin: 8px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ BehEDR Daily Security Report</h1>
            <p>{date_str}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Summary</h2>
                <div class="stats-grid">
                    <div class="stat-box critical">
                        <div class="stat-number">{critical}</div>
                        <div class="stat-label">CRITICAL</div>
                    </div>
                    <div class="stat-box high">
                        <div class="stat-number">{high}</div>
                        <div class="stat-label">HIGH</div>
                    </div>
                    <div class="stat-box medium">
                        <div class="stat-number">{medium}</div>
                        <div class="stat-label">MEDIUM</div>
                    </div>
                    <div class="stat-box low">
                        <div class="stat-number">{low}</div>
                        <div class="stat-label">LOW</div>
                    </div>
                </div>
                
                <div style="text-align: center; margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <strong>Total Alerts:</strong> {total_alerts} ({alert_rate:.2f}% of {stats["total_events"]:,} events)<br>
                    <strong>Trend:</strong> {trend_text}
                </div>
            </div>
            
            <div class="section">
                <h2>🎯 Top Threats Detected</h2>
                <ul>
                    {threats_html}
                </ul>
            </div>
            
            <div class="section">
                <h2>💻 Most Targeted Systems</h2>
                <ul>
                    {systems_html}
                </ul>
            </div>
            
            <div class="section">
                <h2>🔧 Actions Taken</h2>
                <ul>
                    <li><strong>Auto-Responses:</strong> {stats["auto_responses"]} processes terminated</li>
                    <li><strong>False Positives:</strong> {stats["false_positives"]} alerts suppressed</li>
                    <li><strong>Active Incidents:</strong> {stats["active_incidents"]} under investigation</li>
                </ul>
            </div>
            
            {f'<div class="highlight"><strong>⚠️ Action Required:</strong> {stats["active_incidents"]} incident(s) require investigation.</div>' if stats["active_incidents"] > 0 else ''}
            
            <div style="text-align: center; margin-top: 30px;">
                <a href="{SERVER_URL}/api/alerts?last=24h" class="btn">View All Alerts</a>
                <a href="{SERVER_URL}/api/incidents" class="btn">Manage Incidents</a>
                <a href="{SERVER_URL}/" class="btn">Open Dashboard</a>
            </div>
        </div>
        
        <div class="footer">
            <p>BehEDR Security Platform | Automated Daily Report</p>
            <p style="font-size: 12px; color: #999;">To unsubscribe or change settings, contact your administrator</p>
        </div>
    </div>
</body>
</html>'''
    
    return html


def send_digest_email(stats, date_str):
    """Send the digest email"""
    if not SMTP_USER or not SMTP_PASS or not EMAILS[0]:
        print("[DIGEST] Email not configured (missing SMTP settings)")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[BehEDR] Daily Security Summary - {date_str}"
        msg["From"] = SMTP_FROM
        msg["To"] = ", ".join(EMAILS)
        
        # Generate HTML
        html_body = format_html_email(stats, date_str)
        msg.attach(MIMEText(html_body, "html"))
        
        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        
        print(f"[DIGEST] Email sent successfully to {len(EMAILS)} recipient(s)")
        return True
        
    except Exception as e:
        print(f"[DIGEST] Failed to send email: {e}")
        return False


def should_send_now():
    """Check if it's time to send the digest"""
    now = datetime.datetime.now()
    target_hour, target_minute = map(int, SEND_TIME.split(":"))
    
    # Send if current time matches target time (within 1 minute)
    return (now.hour == target_hour and 
            abs(now.minute - target_minute) < 1)


def digest_loop():
    """Background thread that sends daily digest"""
    print(f"[DIGEST] Scheduler started. Will send daily at {SEND_TIME}")
    
    last_send_date = None
    
    while True:
        try:
            if should_send_now():
                today = datetime.date.today().isoformat()
                
                # Only send once per day
                if last_send_date != today:
                    print(f"[DIGEST] Generating daily report for {today}...")
                    stats = get_daily_stats()
                    send_digest_email(stats, today)
                    last_send_date = today
            
            # Check every 30 seconds
            time.sleep(30)
            
        except Exception as e:
            print(f"[DIGEST] Error in digest loop: {e}")
            time.sleep(60)


def start_digest_scheduler():
    """Start the digest scheduler (call from server/__init__.py)"""
    if not ENABLED:
        print("[DIGEST] Daily email digest disabled (set EDR_DIGEST_ENABLED=true to enable)")
        return
    
    if not SMTP_USER or not EMAILS[0]:
        print("[DIGEST] Email digest enabled but not configured (missing SMTP_USER or EDR_DIGEST_EMAILS)")
        return
    
    thread = threading.Thread(
        target=digest_loop,
        name="EmailDigestThread",
        daemon=True
    )
    thread.start()
    print(f"[DIGEST] ✅ Email digest enabled. Recipients: {', '.join(EMAILS)}")


# Manual test function
def send_test_digest():
    """Send a test digest email (for testing)"""
    print("[DIGEST] Generating test digest...")
    stats = get_daily_stats()
    today = datetime.date.today().isoformat()
    return send_digest_email(stats, today)


if __name__ == "__main__":
    # Test mode
    print("Testing email digest...")
    if send_test_digest():
        print("✓ Test email sent successfully!")
    else:
        print("✗ Test email failed")
