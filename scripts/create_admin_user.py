#!/usr/bin/env python3
"""
Script to create an admin user in Supabase
"""

import os
import sys
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

def create_admin_user():
    """Create admin user in Supabase"""
    
    # Supabase configuration
    supabase_url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    if not supabase_url or not service_key:
        print("Error: Missing Supabase configuration")
        print(f"NEXT_PUBLIC_SUPABASE_URL: {'✓' if supabase_url else '✗'}")
        print(f"SUPABASE_SERVICE_ROLE_KEY: {'✓' if service_key else '✗'}")
        return False
    
    try:
        # Create Supabase client with service role key for admin operations
        supabase: Client = create_client(supabase_url, service_key)
        
        # Admin credentials
        admin_email = "admin@sentrysearch.com"
        admin_password = "SentrySearch2025Admin!"
        
        print("Creating admin user...")
        
        # Create admin user
        response = supabase.auth.admin.create_user({
            "email": admin_email,
            "password": admin_password,
            "email_confirm": True,  # Skip email confirmation
            "user_metadata": {
                "name": "SentrySearch Admin",
                "role": "admin"
            }
        })
        
        if response.user:
            print(f"Admin user created successfully!")
            print(f"Email: {admin_email}")
            print(f"Password: {admin_password}")
            print(f"User ID: {response.user.id}")
            print("")
            print("You can now sign in to SentrySearch with these credentials.")
            return True
        else:
            print("Failed to create admin user")
            return False
            
    except Exception as e:
        print(f"Error creating admin user: {e}")
        # If user already exists, that's OK
        if "already registered" in str(e).lower() or "already exists" in str(e).lower():
            print(f"Admin user already exists. Use: {admin_email} / {admin_password}")
            return True
        return False

def main():
    print("SentrySearch Admin User Creation")
    print("=" * 40)
    
    success = create_admin_user()
    
    if success:
        print("\nAdmin user setup complete!")
        print("You can now access SentrySearch with admin privileges.")
        return 0
    else:
        print("\nAdmin user creation failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())