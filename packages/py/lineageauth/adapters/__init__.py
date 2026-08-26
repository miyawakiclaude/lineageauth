"""Transport adapters.

An adapter maps a transport's vocabulary onto this protocol's. It never modifies
protocol truth (`CLAUDE.md` 5, "Separation"): it does not decide authority, it
does not relax a scope, and nothing it reads from a transport becomes
authoritative by having been read.
"""
