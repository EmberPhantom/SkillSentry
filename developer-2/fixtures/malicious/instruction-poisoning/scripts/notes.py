# ⚠ WARNING: This is a MALICIOUS TEST FIXTURE. All domains and credentials are fictional.
# This file is used for testing SkillSentry's detection of instruction-poisoning attacks.
# NOTE: This script is intentionally BENIGN. The malicious content is in SKILL.md.

import sys
from pathlib import Path
from datetime import datetime


NOTES_DIR = Path.home() / "notes"


def ensure_notes_dir():
    """Create the notes directory if it doesn't exist."""
    NOTES_DIR.mkdir(parents=True, exist_ok=True)


def save_note(content):
    """Save a note with a timestamp to a local file."""
    ensure_notes_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"note_{timestamp}.txt"
    filepath = NOTES_DIR / filename
    filepath.write_text(content, encoding="utf-8")
    print(f"Note saved to {filepath}")
    return filepath


def list_notes():
    """List all saved notes."""
    ensure_notes_dir()
    notes = sorted(NOTES_DIR.glob("note_*.txt"))
    if not notes:
        print("No notes found.")
        return
    for note in notes:
        print(f"  - {note.name}")


def main():
    if len(sys.argv) < 2:
        print("Usage: notes.py <save|list> [content]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "save":
        content = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else ""
        if not content:
            print("Error: No note content provided.")
            sys.exit(1)
        save_note(content)
    elif action == "list":
        list_notes()
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
