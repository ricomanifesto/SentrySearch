#!/usr/bin/env python3
"""
Direct database script to update threat categorizations.
This bypasses the ORM and directly updates the production database.
"""

import os
import psycopg
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def categorize_tool(tool_name):
    """Simple categorization logic matching the report_service.py logic"""
    if not tool_name:
        return ('unknown', 'unknown')
    
    tool_lower = tool_name.lower().strip()
    
    # Malware indicators
    malware_indicators = [
        'ransomware', 'trojan', 'backdoor', 'rat', 'rootkit', 'spyware', 'adware',
        'worm', 'virus', 'botnet', 'cryptominer', 'stealer', 'loader', 'dropper',
        'shadowpad', 'cobalt strike', 'meterpreter', 'empire', 'mimikatz', 'lazarus',
        'apt', 'carbanak', 'emotet', 'trickbot', 'ryuk', 'conti', 'lockbit',
        'stealc', 'bumblebee', 'redline', 'azorult', 'formbook', 'agent tesla',
        'nanocore', 'njrat', 'darkcomet', 'poison ivy', 'blackrat'
    ]
    
    # Legitimate software indicators
    legitimate_indicators = [
        'windows', 'microsoft', 'office', 'outlook', 'excel', 'word', 'powershell',
        'cmd', 'notepad', 'explorer', 'chrome', 'firefox', 'safari', 'adobe',
        'java', 'python', 'nodejs', 'git', 'docker', 'kubernetes', 'jenkins',
        'sharepoint', 'exchange', 'active directory', 'ldap', 'ssh', 'ftp', 'sftp',
        'vmware', 'virtualbox', 'hyper-v', 'citrix', 'remote desktop', 'vnc',
        'teamviewer', 'anydesk', 'logmein', 'webex', 'zoom', 'slack', 'teams',
        'sap', 'oracle', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch',
        'apache', 'nginx', 'iis', 'tomcat', 'node', 'express', 'react', 'angular',
        'get-aduser', 'nltest', 'net user', 'whoami', 'ipconfig', 'netstat',
        'ping', 'tracert', 'nslookup', 'runas', 'tasklist', 'services'
    ]
    
    # Threat group indicators
    threat_group_indicators = [
        'lazarus', 'apt1', 'apt28', 'apt29', 'apt34', 'apt40', 'fancy bear',
        'cozy bear', 'carbanak', 'fin7', 'fin8', 'wizard spider', 'sandworm',
        'turla', 'equation group', 'darkhydrus', 'mustang panda', 'kimsuky',
        'scattered spider'
    ]
    
    # Check for malware
    for indicator in malware_indicators:
        if indicator in tool_lower:
            if any(word in tool_lower for word in ['ransomware', 'ryuk', 'conti', 'lockbit']):
                return ('malware', 'ransomware')
            elif any(word in tool_lower for word in ['rat', 'backdoor', 'remote access']):
                return ('malware', 'remote_access_trojan')
            elif any(word in tool_lower for word in ['trojan', 'stealer', 'stealc', 'redline']):
                return ('malware', 'trojan')
            elif any(word in tool_lower for word in ['apt', 'advanced persistent']):
                return ('malware', 'apt_malware')
            elif any(word in tool_lower for word in ['botnet', 'bot']):
                return ('malware', 'botnet')
            elif any(word in tool_lower for word in ['framework', 'cobalt', 'empire', 'meterpreter']):
                return ('malware', 'post_exploitation_framework')
            else:
                return ('malware', 'malware')
    
    # Check for threat groups
    for indicator in threat_group_indicators:
        if indicator in tool_lower:
            return ('threat_group', 'threat_actor')
    
    # Check for legitimate software
    for indicator in legitimate_indicators:
        if indicator in tool_lower:
            if any(word in tool_lower for word in ['windows', 'cmd', 'powershell', 'net ', 'runas', 'nltest', 'get-aduser']):
                return ('legitimate_software', 'system_administration')
            elif any(word in tool_lower for word in ['office', 'word', 'excel', 'outlook', 'sharepoint']):
                return ('legitimate_software', 'productivity_software')
            elif any(word in tool_lower for word in ['chrome', 'firefox', 'safari', 'browser']):
                return ('legitimate_software', 'web_browser')
            elif any(word in tool_lower for word in ['ssh', 'ftp', 'remote', 'vnc', 'teamviewer', 'anydesk']):
                return ('legitimate_software', 'remote_access')
            elif any(word in tool_lower for word in ['vmware', 'docker', 'kubernetes', 'virtualization']):
                return ('legitimate_software', 'virtualization')
            elif any(word in tool_lower for word in ['apache', 'nginx', 'iis', 'server']):
                return ('legitimate_software', 'server_software')
            else:
                return ('legitimate_software', 'legitimate_software')
    
    return ('unknown', 'unknown')


def main():
    """Direct database update"""
    # Database connection
    db_url = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    
    print("SentrySearch Direct Database Categorization Update")
    print("=" * 60)
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # Get all reports with unknown categories
                cur.execute("""
                    SELECT id, tool_name, category, threat_type 
                    FROM reports 
                    WHERE category IN ('unknown', '') OR category IS NULL 
                       OR threat_type IN ('unknown', '') OR threat_type IS NULL
                    ORDER BY created_at DESC
                """)
                
                reports = cur.fetchall()
                print(f"Found {len(reports)} reports to update")
                
                updated_count = 0
                for report_id, tool_name, old_category, old_threat_type in reports:
                    # Get new categorization
                    new_category, new_threat_type = categorize_tool(tool_name)
                    
                    # Only update if different
                    if new_category != old_category or new_threat_type != old_threat_type:
                        cur.execute("""
                            UPDATE reports 
                            SET category = %s, threat_type = %s 
                            WHERE id = %s
                        """, (new_category, new_threat_type, report_id))
                        
                        print(f"Updated '{tool_name}': '{old_category}' -> '{new_category}', '{old_threat_type}' -> '{new_threat_type}'")
                        updated_count += 1
                
                # Commit changes
                conn.commit()
                print(f"\nSuccessfully updated {updated_count} reports")
                
                # Show new distribution
                cur.execute("""
                    SELECT threat_type, COUNT(*) 
                    FROM reports 
                    WHERE threat_type IS NOT NULL AND threat_type != ''
                    GROUP BY threat_type 
                    ORDER BY COUNT(*) DESC
                """)
                
                print("\nNew Threat Distribution:")
                for threat_type, count in cur.fetchall():
                    print(f"  {threat_type}: {count}")
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    print("\nCategorization update complete!")
    return 0


if __name__ == "__main__":
    exit(main())