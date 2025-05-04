"""
Utility script to generate JWT tokens for admin users.
Usage:
  python gen_token.py <ADMIN_ID> [--refresh] [--expiration=SECONDS]
Set environment variable JWT_SECRET to the secret used by the app.
"""
import os
import sys
import argparse

# Add parent directory to path to import from bot package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bot.security import JWTHandler
from config import config

def main():
    parser = argparse.ArgumentParser(description='Generate JWT tokens for admin authentication')
    parser.add_argument('admin_id', type=int, help='Admin user ID')
    parser.add_argument('--refresh', action='store_true', help='Generate a refresh token instead of access token')
    parser.add_argument('--expiration', type=int, help='Custom token expiration in seconds')
    args = parser.parse_args()
    
    # Use config.JWT_SECRET or environment variable
    secret = config.JWT_SECRET or os.getenv('JWT_SECRET')
    if not secret:
        print("Error: JWT_SECRET not set in config or environment variables.")
        sys.exit(1)
    
    # Create JWT handler
    jwt_handler = JWTHandler(secret)
    
    # Create token with expiration
    expiration = args.expiration
    if args.refresh:
        if expiration is None:
            expiration = config.JWT_REFRESH_EXPIRATION
        token = jwt_handler.create_refresh_token(args.admin_id, expiration)
        token_type = "refresh"
    else:
        if expiration is None:
            expiration = config.JWT_EXPIRATION
        token = jwt_handler.create_token(args.admin_id, expiration)
        token_type = "access"
    
    print(f"{token_type.capitalize()} token for admin_id {args.admin_id}:")
    print(token)
    print(f"Token will expire in {expiration} seconds")
    
    # If generating access token, also show a refresh token
    if not args.refresh:
        refresh_token = jwt_handler.create_refresh_token(args.admin_id)
        print("\nRefresh token (valid for 7 days):")
        print(refresh_token)
        print("Use this refresh token to obtain new access tokens without re-authentication.")

if __name__ == "__main__":
    main()