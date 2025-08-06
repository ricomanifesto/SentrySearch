#!/usr/bin/env python3
"""
Script to update existing reports with proper threat categorizations.
Run this to fix the threat distribution showing all "unknown" categories.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from storage.report_service import report_service


def main():
    """Update existing report categorizations."""
    print("SentrySearch Categorization Update")
    print("=" * 50)
    
    try:
        # Test database connection
        if not report_service.test_connection():
            print("Database connection failed. Please check your configuration.")
            return 1
        
        print("Database connection successful")
        
        # Show current stats
        print("\nCurrent Threat Distribution:")
        current_stats = report_service.get_threat_type_stats()
        if current_stats:
            for threat_type, count in current_stats.items():
                print(f"   {threat_type}: {count}")
        else:
            print("   No threat type data found")
        
        # Get all reports for inspection
        print("\nInspecting all reports...")
        all_reports = report_service.list_reports(limit=100, sort_by="created_at", sort_order="desc")
        
        print(f"Found {len(all_reports)} reports to analyze")
        for report in all_reports[:5]:  # Show first 5
            category, threat_type = report_service.categorize_tool(report['tool_name'])
            print(f"  '{report['tool_name']}' -> category: '{category}', threat_type: '{threat_type}'")
        
        # Run categorization update
        print("\nUpdating report categorizations...")
        updated_count = report_service.update_existing_categorizations()
        
        if updated_count > 0:
            print(f"Successfully updated {updated_count} reports")
            
            # Show updated stats
            print("\nUpdated Threat Distribution:")
            updated_stats = report_service.get_threat_type_stats()
            for threat_type, count in updated_stats.items():
                print(f"   {threat_type}: {count}")
        else:
            print("No reports needed categorization updates")
        
        print("\nCategorization update complete!")
        return 0
        
    except Exception as e:
        print(f"Error during categorization update: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())