"""
Supabase Authentication Integration for FastAPI

Handles JWT verification and user API key retrieval.
"""

import os
import logging
import jwt
from fastapi import HTTPException, Header, Depends
from typing import Optional, Dict, Any
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

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
            user_id=user.id, email=user.email, metadata=user.user_metadata or {}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.warning(
            "Token verification failed during Supabase auth check: %s",
            type(e).__name__,
        )
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# Optional dependency for routes that don't require authentication
async def get_optional_user(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Optional[AuthenticatedUser]:
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
