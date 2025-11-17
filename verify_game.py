#!/usr/bin/env python3
"""
Script for verifying game fairness through Legit Check
Uses commit-reveal scheme for verification

This script verifies that a game was fair by:
1. Checking that commit_hash matches the calculated hash from (seed:game_id:created_at)
2. Verifying that the calculated winner_cell matches the claimed winner_cell

Usage:
    python3 verify_game.py <game_id> <commit_hash> <revealed_seed> <created_at> <winner_cell>

Example:
    python3 verify_game.py 137 a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 \\
      1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3 \\
      "2025-11-17T01:00:00" 42

Parameters:
    game_id      - Game ID (positive integer)
    commit_hash  - Commit hash from database (64 hex characters)
    revealed_seed - Revealed game seed (64 hex characters)
    created_at   - Game creation time (ISO 8601 format or 'YYYY-MM-DD HH:MM:SS')
    winner_cell  - Winner cell number (1-64)

Requirements:
    - Python 3.6+
    - Standard library only (no external dependencies)

Author:
    Sapper Game Project
"""

import sys
import hashlib
import re
from datetime import datetime
from typing import Dict, Optional, Tuple


# Constants
FIELD_SIZE = 64
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')


def validate_hex_string(value: str, name: str, expected_length: int = 64) -> str:
    """
    Validate that a string is a valid hexadecimal string of expected length
    
    Args:
        value: String to validate
        name: Parameter name for error messages
        expected_length: Expected length of the hex string
        
    Returns:
        Normalized hex string (lowercase)
        
    Raises:
        ValueError: If validation fails
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string, got {type(value).__name__}")
    
    if not value:
        raise ValueError(f"{name} cannot be empty")
    
    if len(value) != expected_length:
        raise ValueError(
            f"{name} must be exactly {expected_length} hex characters, "
            f"got {len(value)} characters"
        )
    
    if not HEX_PATTERN.match(value):
        raise ValueError(
            f"{name} must contain only hexadecimal characters (0-9, a-f, A-F), "
            f"got: {value[:20]}..."
        )
    
    return value.lower()


def validate_game_id(game_id: int) -> int:
    """
    Validate that game_id is a positive integer
    
    Args:
        game_id: Game ID to validate
        
    Returns:
        Validated game_id
        
    Raises:
        ValueError: If validation fails
    """
    if not isinstance(game_id, int):
        raise ValueError(f"game_id must be an integer, got {type(game_id).__name__}")
    
    if game_id <= 0:
        raise ValueError(f"game_id must be a positive integer, got {game_id}")
    
    return game_id


def validate_winner_cell(winner_cell: int) -> int:
    """
    Validate that winner_cell is an integer between 1 and 64
    
    Args:
        winner_cell: Winner cell number to validate
        
    Returns:
        Validated winner_cell
        
    Raises:
        ValueError: If validation fails
    """
    if not isinstance(winner_cell, int):
        raise ValueError(
            f"winner_cell must be an integer, got {type(winner_cell).__name__}"
        )
    
    if winner_cell < 1 or winner_cell > FIELD_SIZE:
        raise ValueError(
            f"winner_cell must be between 1 and {FIELD_SIZE}, got {winner_cell}"
        )
    
    return winner_cell


def parse_datetime(date_str: str) -> datetime:
    """
    Parse date string into datetime object with validation
    
    Supports formats:
    - ISO 8601: "2025-11-17T01:00:00" or "2025-11-17T01:00:00+00:00" or "2025-11-17T01:00:00Z"
    - Standard: "2025-11-17 01:00:00"
    
    Args:
        date_str: Date string to parse
        
    Returns:
        Parsed datetime object
        
    Raises:
        ValueError: If parsing fails or date is invalid
    """
    if not isinstance(date_str, str):
        raise ValueError(f"created_at must be a string, got {type(date_str).__name__}")
    
    if not date_str.strip():
        raise ValueError("created_at cannot be empty")
    
    # Try ISO 8601 format first
    if 'T' in date_str:
        try:
            # Handle Z suffix (UTC)
            normalized = date_str.replace('Z', '+00:00')
            return datetime.fromisoformat(normalized)
        except ValueError as e:
            raise ValueError(
                f"Failed to parse ISO 8601 date '{date_str}': {e}. "
                f"Expected format: 'YYYY-MM-DDTHH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS+HH:MM'"
            )
    else:
        # Try standard format
        try:
            return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except ValueError as e:
            raise ValueError(
                f"Failed to parse date '{date_str}': {e}. "
                f"Expected format: 'YYYY-MM-DD HH:MM:SS' or ISO 8601 format"
            )


def calculate_winner_cell_from_seed(game_seed: str) -> int:
    """
    Deterministic calculation of winner_cell from seed
    
    This function implements the same algorithm as the server:
    1. Takes first 16 hex characters (8 bytes) from seed
    2. Converts to integer
    3. Calculates: (seed_int % FIELD_SIZE) + 1
    
    Args:
        game_seed: Hex string seed (64 characters, validated)
        
    Returns:
        Winner cell number (1-64)
        
    Raises:
        ValueError: If seed is invalid or calculation fails
    """
    if not game_seed or len(game_seed) < 16:
        raise ValueError(
            f"game_seed must be at least 16 hex characters for calculation, "
            f"got {len(game_seed) if game_seed else 0} characters"
        )
    
    try:
        # Take first 16 hex characters (8 bytes) for calculation
        seed_hex = game_seed[:16]
        seed_int = int(seed_hex, 16)
    except ValueError as e:
        raise ValueError(
            f"Failed to convert seed prefix '{game_seed[:16]}' to integer: {e}"
        )
    except Exception as e:
        raise ValueError(f"Unexpected error calculating winner_cell: {e}")
    
    # Calculate winner_cell deterministically
    # This matches the server-side implementation exactly
    winner_cell = (seed_int % FIELD_SIZE) + 1
    
    return winner_cell


def calculate_commit_hash(game_seed: str, game_id: int, created_at: datetime) -> str:
    """
    Calculate commit hash for fairness verification
    
    This function implements the same algorithm as the server:
    commit_data = f"{game_seed}:{game_id}:{created_at.isoformat()}"
    commit_hash = SHA256(commit_data).hexdigest()
    
    Args:
        game_seed: Hex string seed (validated)
        game_id: Game ID (validated)
        created_at: Game creation time (validated)
        
    Returns:
        SHA256 hash in hex format (64 characters)
        
    Raises:
        ValueError: If any parameter is invalid
    """
    if not game_seed:
        raise ValueError("game_seed cannot be empty")
    
    if not game_id or game_id <= 0:
        raise ValueError(f"game_id must be positive, got {game_id}")
    
    if not isinstance(created_at, datetime):
        raise ValueError(
            f"created_at must be a datetime object, got {type(created_at).__name__}"
        )
    
    try:
        # Form string for hashing (matches server implementation exactly)
        commit_data = f"{game_seed}:{game_id}:{created_at.isoformat()}"
        
        # Calculate SHA256 hash
        commit_hash = hashlib.sha256(commit_data.encode('utf-8')).hexdigest()
        
        return commit_hash
    except Exception as e:
        raise ValueError(f"Failed to calculate commit_hash: {e}")


def verify_game(
    game_id: int,
    commit_hash: str,
    revealed_seed: str,
    created_at_str: str,
    winner_cell: int
) -> Dict[str, any]:
    """
    Verify game fairness through commit-reveal scheme
    
    This function performs two critical checks:
    1. Verifies that commit_hash matches the calculated hash from (seed:game_id:created_at)
    2. Verifies that the calculated winner_cell matches the claimed winner_cell
    
    Args:
        game_id: Game ID
        commit_hash: Stored commit hash from database
        revealed_seed: Revealed game seed
        created_at_str: Game creation time (string)
        winner_cell: Claimed winner_cell
        
    Returns:
        Dict with verification results containing:
        - game_id: Game ID
        - commit_hash: Original commit hash
        - calculated_hash: Calculated hash from seed
        - hash_matches: Boolean indicating if hashes match
        - revealed_seed: Revealed seed
        - winner_cell: Claimed winner cell
        - calculated_winner_cell: Calculated winner cell from seed
        - winner_cell_matches: Boolean indicating if cells match
        - created_at: Parsed creation time (ISO format)
        - is_legit: Boolean indicating if game passed all checks
        - error: Error message (if verification failed)
        
    Raises:
        ValueError: If any parameter validation fails
    """
    try:
        # Validate all input parameters
        validated_game_id = validate_game_id(game_id)
        validated_commit_hash = validate_hex_string(commit_hash, "commit_hash", 64)
        validated_seed = validate_hex_string(revealed_seed, "revealed_seed", 64)
        validated_winner_cell = validate_winner_cell(winner_cell)
        created_at = parse_datetime(created_at_str)
        
        # Calculate hash from revealed seed
        calculated_hash = calculate_commit_hash(
            validated_seed,
            validated_game_id,
            created_at
        )
        
        # Calculate winner_cell from seed
        calculated_winner_cell = calculate_winner_cell_from_seed(validated_seed)
        
        # Perform verification checks
        hash_matches = calculated_hash == validated_commit_hash
        winner_cell_matches = calculated_winner_cell == validated_winner_cell
        is_legit = hash_matches and winner_cell_matches
        
        return {
            'game_id': validated_game_id,
            'commit_hash': validated_commit_hash,
            'calculated_hash': calculated_hash,
            'hash_matches': hash_matches,
            'revealed_seed': validated_seed,
            'winner_cell': validated_winner_cell,
            'calculated_winner_cell': calculated_winner_cell,
            'winner_cell_matches': winner_cell_matches,
            'created_at': created_at.isoformat(),
            'is_legit': is_legit
        }
    except ValueError as e:
        # Re-raise validation errors as-is
        return {
            'error': str(e),
            'is_legit': False
        }
    except Exception as e:
        # Catch any unexpected errors
        return {
            'error': f"Unexpected error during verification: {str(e)}",
            'is_legit': False
        }


def main() -> None:
    """
    Main function for command line execution
    
    Parses command line arguments, validates them, performs verification,
    and outputs results in a human-readable format.
    """
    if len(sys.argv) != 6:
        print("Usage: python3 verify_game.py <game_id> <commit_hash> <revealed_seed> <created_at> <winner_cell>")
        print("\nExample:")
        print('  python3 verify_game.py 137 a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 \\')
        print('    1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3 \\')
        print('    "2025-11-17T01:00:00" 42')
        print("\nParameters:")
        print("  game_id      - Game ID (positive integer)")
        print("  commit_hash  - Commit hash from database (64 hex characters)")
        print("  revealed_seed - Revealed game seed (64 hex characters)")
        print("  created_at   - Game creation time (ISO format or 'YYYY-MM-DD HH:MM:SS')")
        print("  winner_cell  - Winner cell number (1-64)")
        sys.exit(1)
    
    try:
        # Parse command line arguments
        try:
            game_id = int(sys.argv[1])
        except ValueError:
            print(f"❌ Error: game_id must be an integer, got '{sys.argv[1]}'")
            sys.exit(1)
        
        commit_hash = sys.argv[2]
        revealed_seed = sys.argv[3]
        created_at_str = sys.argv[4]
        
        try:
            winner_cell = int(sys.argv[5])
        except ValueError:
            print(f"❌ Error: winner_cell must be an integer, got '{sys.argv[5]}'")
            sys.exit(1)
        
        # Perform verification
        result = verify_game(
            game_id,
            commit_hash,
            revealed_seed,
            created_at_str,
            winner_cell
        )
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            sys.exit(1)
        
        # Output results
        print("=" * 80)
        print("🔐 GAME FAIRNESS VERIFICATION (LEGIT CHECK)")
        print("=" * 80)
        print(f"\n📊 Game data:")
        print(f"  Game ID: {result['game_id']}")
        print(f"  Winner cell: {result['winner_cell']}")
        print(f"  Created at: {result['created_at']}")
        
        print(f"\n🔐 Verification data:")
        print(f"  Commit Hash (from DB): {result['commit_hash']}")
        print(f"  Revealed Seed: {result['revealed_seed']}")
        
        print(f"\n✅ Verification results:")
        print(f"  Calculated Hash: {result['calculated_hash']}")
        print(f"  Hash matches: {'✅ YES' if result['hash_matches'] else '❌ NO'}")
        print(f"  Calculated cell: {result['calculated_winner_cell']}")
        print(f"  Cell matches: {'✅ YES' if result['winner_cell_matches'] else '❌ NO'}")
        
        print(f"\n{'=' * 80}")
        if result['is_legit']:
            print("✅ GAME IS FAIR! All checks passed.")
        else:
            print("❌ GAME FAILED VERIFICATION!")
            if not result['hash_matches']:
                print("   - Commit hash does not match")
            if not result['winner_cell_matches']:
                print("   - Winner cell does not match")
        print("=" * 80)
        
        sys.exit(0 if result['is_legit'] else 1)
        
    except KeyboardInterrupt:
        print("\n\n❌ Verification interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
