# Third-party notices

RAA orchestrates or documents third-party engines, libraries and standards. They
are not relicensed by RAA.

- Engine names, tiers, integration modes and licences are recorded in
  `src/raa/services/engines.py` and documented in `docs/ARCHITECTURE.md`.
- Copyleft engines (for example GPL-licensed APKiD, MobSF and Quark) must remain
  separate processes or user-supplied installations. They are not linked into
  the RAA core.
- Engine binaries, signatures, rules and models are not committed to this
  repository.
- Verify each engine's current licence and redistribution terms before shipping
  a bundle. `admin_license_report` is an inventory, not legal advice.

Reference material in `docs/Reference Application/` is a third-party analysis
sample retained for internal research. It is not part of the RAA runtime and must
not be redistributed without permission from its owner.
