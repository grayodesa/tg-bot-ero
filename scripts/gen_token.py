"""
Utility script to generate JWT tokens for admin users.
Usage:
  python gen_token.py <ADMIN_ID> [EXPIRATION_SECONDS]
Set environment variable JWT_SECRET to the secret used by the app.
"""
import os
import sys
import time

# Add parent directory to path to import from bot package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bot.auth import create_jwt
from config import config

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python gen_token.py <ADMIN_ID> [EXPIRATION_SECONDS]")
        sys.exit(1)
    
    try:
        admin_id = int(sys.argv[1])
    except ValueError:
        print("ADMIN_ID must be an integer.")
        sys.exit(1)
    
    # Use custom expiration if provided
    expiration_seconds = None
    if len(sys.argv) == 3:
        try:
            expiration_seconds = int(sys.argv[2])
        except ValueError:
            print("EXPIRATION_SECONDS must be an integer.")
            sys.exit(1)
    
    # Use config.JWT_SECRET or environment variable
    secret = config.JWT_SECRET or os.getenv('JWT_SECRET')
    if not secret:
        print("Error: JWT_SECRET not set in config or environment variable.")
        sys.exit(1)
    
    # Create token with expiration
    token = create_jwt(admin_id, secret, expiration_seconds)
    
    print(f"Token for admin_id {admin_id}:")
    print(token)
    
    # Show expiration info
    if expiration_seconds:
        print(f"Token will expire in {expiration_seconds} seconds")
    else:
        print(f"Token will expire in {config.JWT_EXPIRATION} seconds (default)")

if __name__ == "__main__":
    main()