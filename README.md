# 🔐 Legit Check - Game Fairness Verification

## 📖 Description

Legit Check is a game fairness verification system using a **commit-reveal scheme**. It guarantees that the game result was determined before the game started and could not be changed afterwards.

## 🎯 How It Works

1. **When creating a game:**
   - A cryptographically secure `seed` is generated (64 hex characters)
   - `winner_cell` is calculated deterministically from `seed`
   - `commit_hash = SHA256(seed:game_id:created_at)` is calculated
   - `commit_hash` is saved to the database
   - `seed` is temporarily stored in Redis (not published)

2. **After game completion:**
   - `seed` is published to the database
   - Users can verify game fairness

3. **Fairness verification:**
   - `commit_hash` is calculated from the published `seed`
   - Compared with the stored `commit_hash`
   - `winner_cell` is calculated from `seed`
   - Compared with the actual `winner_cell`

## 🚀 Usage

### Via Web Interface

1. Open the **"Game History"** section
2. Find a completed game
3. Click the **"🔐 Legit Check"** button
4. View the verification results

### Via Command Line

Use the `verify_game.py` script to verify a game. All required data can be obtained from the web interface:

```bash
python3 verify_game.py <game_id> <commit_hash> <revealed_seed> <created_at> <winner_cell>
```

#### Usage Example:

```bash
python3 verify_game.py 137 \
  a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 \
  1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3 \
  "2025-11-17T01:00:00" \
  42
```

#### Parameters:

- `game_id` - Game ID (number)
- `commit_hash` - Commit hash (64 hex characters)
- `revealed_seed` - Revealed game seed (64 hex characters)
- `created_at` - Game creation time (ISO format: `"2025-11-17T01:00:00"` or `"2025-11-17 01:00:00"`)
- `winner_cell` - Winner cell number (1-64)

#### Where to Get Data:

1. Open the **"Game History"** section in the web interface
2. Find the desired game and click the **"🔐 Legit Check"** button
3. Copy from the opened window:
   - `Commit Hash`
   - `Revealed Seed`
   - `Game ID`
   - `Winner Cell`
   - `Created At`

## 📊 Output Format

The script outputs:

```
================================================================================
🔐 GAME FAIRNESS VERIFICATION (LEGIT CHECK)
================================================================================

📊 Game data:
  Game ID: 137
  Winner cell: 42
  Created at: 2025-11-17T01:00:00

🔐 Verification data:
  Commit Hash (from DB): a1b2c3d4...
  Revealed Seed: 1a2b3c4d5...

✅ Verification results:
  Calculated Hash: a1b2c3d4...
  Hash matches: ✅ YES
  Calculated cell: 42
  Cell matches: ✅ YES

================================================================================
✅ GAME IS FAIR! All checks passed.
================================================================================
```

## 🔍 Verification Algorithm

### 1. Calculate commit_hash

```python
commit_data = f"{game_seed}:{game_id}:{created_at.isoformat()}"
commit_hash = SHA256(commit_data).hexdigest()
```

### 2. Calculate winner_cell

```python
seed_int = int(game_seed[:16], 16)  # First 16 hex characters
winner_cell = (seed_int % 64) + 1    # Cells from 1 to 64
```

### 3. Verification

- `calculated_hash == commit_hash` ✅
- `calculated_winner_cell == winner_cell` ✅

If both checks pass → **Game is fair** ✅

## 🔒 Security

- **Cryptographically secure seed:** Uses `secrets.token_hex(32)` (32 bytes of entropy)
- **Commit-reveal scheme:** `seed` is not published until game completion
- **Determinism:** `winner_cell` is calculated deterministically from `seed`
- **Impossible to forge:** `commit_hash` is calculated using `game_id` and `created_at`

## 📝 Notes

- Legit Check is only available for games created after the system was implemented
- For old games, the message "This game was created before Legit Check implementation" will be shown
- For unfinished games, `seed` is not yet published

## 🛠️ Requirements

- Python 3.6+
- Standard Python library (no external dependencies)

## 📄 License

This script is part of the Sapper Game project and uses the same logic as the server-side application.
