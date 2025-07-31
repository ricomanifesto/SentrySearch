"""
Supabase Authentication Integration for FastAPI

Handles JWT verification and user API key retrieval.
"""

import os
import jwt
from fastapi import HTTPException, Header, Depends
from typing import Optional, Dict, Any
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

# Supabase client setup
supabase_url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not supabase_url or not service_key:
    print("Warning: Missing Supabase configuration. Authentication will not work.")
    print(f"NEXT_PUBLIC_SUPABASE_URL: {'✓' if supabase_url else '✗'}")
    print(f"SUPABASE_SERVICE_ROLE_KEY: {'✓' if service_key else '✗'}")
    supabase = None
else:
    supabase: Client = create_client(supabase_url, service_key)

class AuthenticatedUser:
    """Represents an authenticated user from Supabase"""
    def __init__(self, user_id: str, email: str, metadata: Dict[str, Any] = None):
        self.id = user_id
        self.email = email
        self.metadata = metadata or {}

async def verify_jwt_token(authorization: Optional[str] = Header(None)) -> AuthenticatedUser:
    """
    Verify Supabase JWT token and return authenticated user.
    
    Args:
        authorization: Bearer token from Authorization header
        
    Returns:
        AuthenticatedUser: Verified user information
        
    Raises:
        HTTPException: If token is invalid or missing
    """
    if not supabase:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
        
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    # Extract token from "Bearer <token>" format
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization.split(" ")[1]
    
    try:
        # Verify token with Supabase
        response = supabase.auth.get_user(token)
        
        if not response or not response.user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        user = response.user
        return AuthenticatedUser(
            user_id=user.id,
            email=user.email,
            metadata=user.user_metadata or {}
        )
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")

async def get_user_api_key(user: AuthenticatedUser = Depends(verify_jwt_token)) -> Optional[str]:
    """
    Get user's Anthropic API key from Supabase user_profiles table.
    
    Args:
        user: Authenticated user from JWT verification
        
    Returns:
        str: User's encrypted API key or None if not set
        
    Raises:
        HTTPException: If database query fails
    """
    if not supabase:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
        
    try:
        response = supabase.table('user_profiles').select('anthropic_api_key_encrypted').eq('id', user.id).single().execute()
        
        if response.data and response.data.get('anthropic_api_key_encrypted'):
            return response.data['anthropic_api_key_encrypted']
        
        # If no API key found, raise helpful error
        raise HTTPException(
            status_code=400, 
            detail="No Anthropic API key configured. Please add your API key in Settings."
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve API key: {str(e)}")

# Optional dependency for routes that don't require authentication
async def get_optional_user(authorization: Optional[str] = Header(None, alias="Authorization")) -> Optional[AuthenticatedUser]:
    """
    Optional authentication dependency for routes that work with or without auth.
    
    Args:
        authorization: Optional Bearer token
        
    Returns:
        AuthenticatedUser or None: User if authenticated, None if not
    """
    if not authorization:
        return None
    
    try:
        return await verify_jwt_token(authorization)
    except HTTPException:
        # Return None instead of raising exception for optional auth
        return None