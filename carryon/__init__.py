"""carryon - carry an AI coding agent's working life between machines.

Two halves with opposite safety postures, kept apart on purpose. The Setup
(config, capability, knowledge) is carried plaintext and carryon refuses to
produce one containing a credential. The History (Sessions, with the paths
inside them re-keyed) is always encrypted, and a credential found there is
reported rather than blocked - it records something echoed to a terminal in
the past, which no capture rule can fix. See CONTEXT.md and docs/adr/.
"""

__version__ = "0.1.0"
