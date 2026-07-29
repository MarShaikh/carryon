"""carryon - move an AI coding agent setup to a new machine.

Captures config, capability and knowledge for every agent it finds, refuses to
carry credentials, and records what it deliberately left behind.

It does not move chats or sessions. That is a different problem - it needs path
re-keying inside transcript bodies and a redaction pass - and entangle already
solves it well: https://github.com/gowtham-sai-yadav/claude-teleport
"""

__version__ = "0.1.0"
