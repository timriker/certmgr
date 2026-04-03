# GitHub Copilot Instructions

Whenever you add, remove, or change command-line options in `certmgr.py`, update documentation in all of the following places:

1. The comment block at the top of `certmgr.py` (lists all CLI options)
2. The README.md file (lists and describes all CLI options)
3. The argparse help strings in `certmgr.py` (each option should have a clear help description)

This ensures users and Copilot agents always have accurate, up-to-date information.

**Checklist for future changes:**
- [ ] Update comment block in `certmgr.py`
- [ ] Update README.md CLI options section
- [ ] Update argparse help strings

---

**Copyright and License Reminder:**
- Always include copyright and license information at the top of all project source files and documentation files as appropriate.
- Ensure SPDX license identifiers are present where required.

---

**Additional Best Practices and Instructions:**

- When adding or changing CLI options, always update:
  - The comment block in `certmgr.py`
  - The README.md CLI options section
  - The argparse help strings

- Suppress Python tracebacks in user-facing output; only show clear error messages and summaries.

- Ensure all log messages are clear, deduplicated, and mapped to the correct domain or identifier.

- When updating DNS records for ACME challenges, avoid unnecessary operations for wildcards and ensure correct cleanup logic.

- Always test with `--staging` before switching to production to avoid rate limits and unexpected failures.

- Confirm F5 credentials have the required permissions (full Administrator role).

- Store project instructions in `.github/copilot_instructions.md` for Copilot and automation tools.

---

*This file is placed in `.github/copilot_instructions.md` so GitHub Copilot and other automation tools can automatically read it when the repository is checked out.*
