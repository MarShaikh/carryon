"""carryon - carry an AI coding agent's working life between machines.

Two halves, kept apart on purpose. The Setup (config, capability, knowledge)
is what makes an agent yours; the History (Sessions, with the paths inside
them re-keyed) is what you did with it. Everything carryon carries is
encrypted (ADR-0014), so the halves no longer differ in how they are stored -
they differ in the UNIT they are refused in, which is the thing to hold on to:
a Setup is a replacement and lands whole or not at all, while a History
accumulates and never deletes, so it reports per Session and carries the rest.
A credential is reported in both halves rather than blocked in either - in a
Transcript it records something echoed to a terminal in the past, which no
capture rule can fix. See CONTEXT.md and docs/adr/.
"""

__version__ = "0.1.0"
