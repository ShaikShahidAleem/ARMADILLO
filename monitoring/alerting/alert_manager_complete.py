# monitoring/alerting/alert_manager.py
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional
import json
import asyncio
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiohttp

class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertChannel(Enum):
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SMS = "sms"

@dataclass
class Alert:
    id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str
    timestamp: datetime
    metadata: Dict = None
    resolved: bool = False
    acknowledged: bool = False

@dataclass
class AlertRule:
    name: str
    severity_threshold: AlertSeverity
    channels: List[AlertChannel]
    frequency_limit: Optional[timedelta] = None
    escalation_after: Optional[timedelta] = None
    team: str = "default"

class TieredAlertManager:
    def __init__(self, config_path: str = "config/alerting.json"):
        self.config = self._load_config(config_path)
        self.alert_rules = self._load_alert_rules()
        self.alert_history = []
        self.suppression_cache = {}

    def _load_config(self, config_path: str) -> Dict:
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
            return {"alert_rules": [], "default_frequency_limit_minutes": 60}

    def _load_alert_rules(self) -> Dict[str, AlertRule]:
        rules = {}
        for rule_config in self.config.get('alert_rules', []):
            rule = AlertRule(
                name=rule_config['name'],
                severity_threshold=AlertSeverity(rule_config['severity_threshold']),
                channels=[AlertChannel(ch) for ch in rule_config['channels']],
                frequency_limit=timedelta(minutes=rule_config.get('frequency_limit_minutes', 60)),
                escalation_after=timedelta(minutes=rule_config.get('escalation_after_minutes', 30)),
                team=rule_config.get('team', 'default')
            )
            rules[rule.name] = rule
        return rules

    async def process_alert(self, alert: Alert) -> bool:
        """Process, suppress, and route alerts based on rules"""
        try:
            # Check if alert should be suppressed
            if self._should_suppress(alert):
                print(f"Alert {alert.id} suppressed due to frequency limit")
                return False
            
            # Find matching rules
            matching_rules = self._find_matching_rules(alert)
            
            if not matching_rules:
                print(f"No matching rules for alert {alert.id}")
                return False
            
            # Send notifications through all configured channels
            success = True
            for rule in matching_rules:
                for channel in rule.channels:
                    try:
                        result = await self._send_notification(alert, channel, rule)
                        if not result:
                            success = False
                    except Exception as e:
                        print(f"Error sending to {channel.value}: {e}")
                        success = False
            
            # Store in history
            self.alert_history.append({
                'alert': alert,
                'timestamp': datetime.now(),
                'sent': success
            })
            
            # Update suppression cache
            self._update_suppression_cache(alert)
            
            return success
            
        except Exception as e:
            print(f"Error processing alert {alert.id}: {e}")
            return False
    
    def _should_suppress(self, alert: Alert) -> bool:
        """Check if alert should be suppressed based on frequency limits"""
        cache_key = f"{alert.source}:{alert.severity.value}"
        
        if cache_key in self.suppression_cache:
            last_sent = self.suppression_cache[cache_key]
            frequency_limit = timedelta(minutes=self.config.get('default_frequency_limit_minutes', 60))
            
            if datetime.now() - last_sent < frequency_limit:
                return True
        
        return False
    
    def _update_suppression_cache(self, alert: Alert):
        """Update suppression cache with latest alert timestamp"""
        cache_key = f"{alert.source}:{alert.severity.value}"
        self.suppression_cache[cache_key] = datetime.now()
    
    def _find_matching_rules(self, alert: Alert) -> List[AlertRule]:
        """Find alert rules that match the alert severity"""
        matching = []
        
        severity_order = {
            AlertSeverity.INFO: 0,
            AlertSeverity.LOW: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.CRITICAL: 4
        }
        
        alert_severity_level = severity_order.get(alert.severity, 0)
        
        for rule in self.alert_rules.values():
            rule_severity_level = severity_order.get(rule.severity_threshold, 0)
            if alert_severity_level >= rule_severity_level:
                matching.append(rule)
        
        return matching

    async def _send_notification(self, alert: Alert, channel: AlertChannel, rule: AlertRule) -> bool:
        """Route notification to appropriate channel"""
        try:
            if channel == AlertChannel.EMAIL:
                return await self._send_email(alert, rule)
            elif channel == AlertChannel.SLACK:
                return await self._send_slack(alert, rule)
            elif channel == AlertChannel.PAGERDUTY:
                return await self._send_pagerduty(alert, rule)
            elif channel == AlertChannel.WEBHOOK:
                return await self._send_webhook(alert, rule)
            elif channel == AlertChannel.SMS:
                return await self._send_sms(alert, rule)
            else:
                print(f"Unsupported channel: {channel}")
                return False
        except Exception as e:
            print(f"Error sending notification via {channel.value}: {e}")
            return False

    async def _send_email(self, alert: Alert, rule: AlertRule) -> bool:
        """Send detailed email alerts"""
        try:
            smtp_config = self.config.get('email', {})
            
            if not smtp_config:
                print("Email configuration not found")
                return False
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            msg['From'] = smtp_config.get('from_address', 'alerts@devsecops.local')
            msg['To'] = ', '.join(smtp_config.get('to_addresses', []))
            
            html_body = f"""
            <html>
                <body>
                    <h2 style="color: {'red' if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH] else 'orange'};">
                        Security Alert: {alert.title}
                    </h2>
                    <p><strong>Severity:</strong> {alert.severity.value.upper()}</p>
                    <p><strong>Source:</strong> {alert.source}</p>
                    <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Team:</strong> {rule.team}</p>
                    <hr>
                    <h3>Description:</h3>
                    <p>{alert.description}</p>
                    <hr>
                    <h3>Metadata:</h3>
                    <pre>{json.dumps(alert.metadata or {}, indent=2)}</pre>
                    <hr>
                    <p><em>Alert ID: {alert.id}</em></p>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            with smtplib.SMTP(smtp_config.get('smtp_host', 'localhost'), 
                            smtp_config.get('smtp_port', 587)) as server:
                if smtp_config.get('use_tls', True):
                    server.starttls()
                
                if smtp_config.get('username') and smtp_config.get('password'):
                    server.login(smtp_config['username'], smtp_config['password'])
                
                server.send_message(msg)
            
            print(f"Email sent for alert {alert.id}")
            return True
            
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    async def _send_slack(self, alert: Alert, rule: AlertRule) -> bool:
        """Send formatted Slack messages"""
        try:
            slack_config = self.config.get('slack', {})
            webhook_url = slack_config.get('webhook_url')
            
            if not webhook_url:
                print("Slack webhook URL not configured")
                return False
            
            color_map = {
                AlertSeverity.CRITICAL: '#FF0000',
                AlertSeverity.HIGH: '#FF6600',
                AlertSeverity.MEDIUM: '#FFA500',
                AlertSeverity.LOW: '#FFFF00',
                AlertSeverity.INFO: '#00FF00'
            }
            
            slack_message = {
                "username": "DevSecOps Alert Manager",
                "icon_emoji": ":shield:",
                "attachments": [
                    {
                        "color": color_map.get(alert.severity, '#808080'),
                        "title": f"{alert.severity.value.upper()}: {alert.title}",
                        "text": alert.description,
                        "fields": [
                            {"title": "Source", "value": alert.source, "short": True},
                            {"title": "Team", "value": rule.team, "short": True},
                            {"title": "Alert ID", "value": alert.id, "short": True},
                            {"title": "Timestamp", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), "short": True}
                        ],
                        "footer": "Armadillo DevSecOps",
                        "ts": int(alert.timestamp.timestamp())
                    }
                ]
            }
            
            if alert.metadata:
                slack_message["attachments"][0]["fields"].append({
                    "title": "Metadata",
                    "value": f"```{json.dumps(alert.metadata, indent=2)}```",
                    "short": False
                })
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=slack_message) as response:
                    if response.status == 200:
                        print(f"Slack notification sent for alert {alert.id}")
                        return True
                    else:
                        print(f"Slack API error: {response.status}")
                        return False
                        
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")
            return False
    
    async def _send_pagerduty(self, alert: Alert, rule: AlertRule) -> bool:
        """Send alert to PagerDuty"""
        try:
            pd_config = self.config.get('pagerduty', {})
            integration_key = pd_config.get('integration_key')
            
            if not integration_key:
                print("PagerDuty integration key not configured")
                return False
            
            pd_severity_map = {
                AlertSeverity.CRITICAL: 'critical',
                AlertSeverity.HIGH: 'error',
                AlertSeverity.MEDIUM: 'warning',
                AlertSeverity.LOW: 'info',
                AlertSeverity.INFO: 'info'
            }
            
            pd_event = {
                "routing_key": integration_key,
                "event_action": "trigger",
                "dedup_key": alert.id,
                "payload": {
                    "summary": alert.title,
                    "source": alert.source,
                    "severity": pd_severity_map.get(alert.severity, 'info'),
                    "timestamp": alert.timestamp.isoformat(),
                    "custom_details": {
                        "description": alert.description,
                        "team": rule.team,
                        "metadata": alert.metadata or {}
                    }
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post('https://events.pagerduty.com/v2/enqueue', json=pd_event) as response:
                    if response.status == 202:
                        print(f"PagerDuty alert sent for {alert.id}")
                        return True
                    else:
                        print(f"PagerDuty API error: {response.status}")
                        return False
                        
        except Exception as e:
            print(f"Failed to send PagerDuty alert: {e}")
            return False
    
    async def _send_webhook(self, alert: Alert, rule: AlertRule) -> bool:
        """Send alert to custom webhook"""
        try:
            webhook_config = self.config.get('webhook', {})
            webhook_url = webhook_config.get('url')
            
            if not webhook_url:
                print("Webhook URL not configured")
                return False
            
            payload = {
                "alert_id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "source": alert.source,
                "timestamp": alert.timestamp.isoformat(),
                "team": rule.team,
                "metadata": alert.metadata or {},
                "resolved": alert.resolved,
                "acknowledged": alert.acknowledged
            }
            
            headers = webhook_config.get('headers', {})
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    if 200 <= response.status < 300:
                        print(f"Webhook notification sent for alert {alert.id}")
                        return True
                    else:
                        print(f"Webhook error: {response.status}")
                        return False
                        
        except Exception as e:
            print(f"Failed to send webhook notification: {e}")
            return False
    
    async def _send_sms(self, alert: Alert, rule: AlertRule) -> bool:
        """Send SMS alert (using Twilio)"""
        try:
            sms_config = self.config.get('sms', {})
            
            if not sms_config:
                print("SMS configuration not found")
                return False
            
            message = f"[{alert.severity.value.upper()}] {alert.title}\n{alert.description[:100]}"
            twilio_url = f"https://api.twilio.com/2010-04-01/Accounts/{sms_config.get('account_sid')}/Messages.json"
            
            payload = {
                'From': sms_config.get('from_number'),
                'To': sms_config.get('to_number'),
                'Body': message
            }
            
            auth = aiohttp.BasicAuth(sms_config.get('account_sid'), sms_config.get('auth_token'))
            
            async with aiohttp.ClientSession() as session:
                async with session.post(twilio_url, data=payload, auth=auth) as response:
                    if response.status == 201:
                        print(f"SMS sent for alert {alert.id}")
                        return True
                    else:
                        print(f"SMS API error: {response.status}")
                        return False
                        
        except Exception as e:
            print(f"Failed to send SMS: {e}")
            return False
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged"""
        for entry in self.alert_history:
            if entry['alert'].id == alert_id:
                entry['alert'].acknowledged = True
                print(f"Alert {alert_id} acknowledged")
                return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved"""
        for entry in self.alert_history:
            if entry['alert'].id == alert_id:
                entry['alert'].resolved = True
                print(f"Alert {alert_id} resolved")
                return True
        return False
    
    def get_alert_history(self, hours: int = 24) -> List[Dict]:
        """Get alert history for the last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [entry for entry in self.alert_history if entry['timestamp'] > cutoff]
    
    def get_statistics(self) -> Dict:
        """Get alerting statistics"""
        total_alerts = len(self.alert_history)
        
        if total_alerts == 0:
            return {'total_alerts': 0, 'by_severity': {}, 'success_rate': 0.0}
        
        by_severity = {}
        successful = 0
        
        for entry in self.alert_history:
            severity = entry['alert'].severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
            if entry['sent']:
                successful += 1
        
        return {
            'total_alerts': total_alerts,
            'by_severity': by_severity,
            'success_rate': successful / total_alerts,
            'acknowledged': sum(1 for e in self.alert_history if e['alert'].acknowledged),
            'resolved': sum(1 for e in self.alert_history if e['alert'].resolved)
        }


# Example usage
async def main():
    """Example usage of TieredAlertManager"""
    import os
    os.makedirs('config', exist_ok=True)
    
    config = {
        "alert_rules": [
            {
                "name": "critical_alerts",
                "severity_threshold": "critical",
                "channels": ["slack"],
                "frequency_limit_minutes": 15,
                "team": "security-team"
            },
            {
                "name": "high_alerts",
                "severity_threshold": "high",
                "channels": ["slack"],
                "frequency_limit_minutes": 30,
                "team": "devops-team"
            }
        ],
        "default_frequency_limit_minutes": 60,
        "slack": {
            "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        }
    }
    
    with open('config/alerting.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    manager = TieredAlertManager('config/alerting.json')
    
    alert = Alert(
        id="alert-001",
        title="Suspicious API Activity Detected",
        description="Unusual number of failed authentication attempts from IP 192.168.1.100",
        severity=AlertSeverity.HIGH,
        source="api-gateway",
        timestamp=datetime.now(),
        metadata={"ip_address": "192.168.1.100", "failed_attempts": 50, "time_window": "5 minutes"}
    )
    
    success = await manager.process_alert(alert)
    print(f"\nAlert processed: {success}")
    print(f"\nStatistics:\n{json.dumps(manager.get_statistics(), indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())
