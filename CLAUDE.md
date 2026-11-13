# Repository guidance

Read `AGENTS.md` for repository conventions. For OSCAR managed inhibition changes,
also read `doc/oscar-managed-inhibition.md`; it defines durability, reload ownership,
service authorization, and accepted native lifecycle behavior.

Native alert responses expose additive `startsAtRaw` for exact occurrence lookup;
`startsAt` remains unchanged. The managed-inhibition guide also documents the
shared recorder first/refresh cadence for existing output consumers.
