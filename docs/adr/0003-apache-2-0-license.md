# ADR-0003: License Innsegl under Apache-2.0

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context
Innsegl composes with the SPIFFE/SPIRE and Sigstore ecosystems, both of which are Apache-2.0. The licence chosen at repo creation is effectively permanent for a project meant to become an attribution standard: relicensing later requires the consent of every contributor. Two forces dominate. First, licence friction in the dependency chain — an incompatible or copyleft licence sitting on top of an Apache-2.0 dependency graph creates review burden for every adopter. Second, enterprise legal review: Innsegl is a security tool, and the organizations that most need non-repudiable attribution are exactly the ones whose legal teams gate adoption on the licence text, with an explicit patent grant weighing heavily in that review.

## Decision
**Apache License 2.0**, matching the ecosystem Innsegl composes with — SPIFFE/SPIRE and Sigstore are Apache-2.0, so there is zero license friction in the dependency chain, and the explicit patent grant matters for a security tool enterprises must clear through legal review.

## Alternatives considered
- **MIT**: fine, but no patent grant — strictly less protective for the same permissiveness.
- **AGPL**: would maximize contribution-back pressure but kill exactly the enterprise adoption an attribution standard needs, and mixes poorly with the Apache ecosystem it embeds.

## Consequences
Every source file gets the SPDX header (`SPDX-License-Identifier: Apache-2.0`), and CI gates on its presence; a `NOTICE` file carries attribution as Apache-2.0 prescribes and must be kept current as dependencies and contributors change. Downstream adopters — including proprietary ones — may embed Innsegl without a copyleft obligation, which is the point: an attribution standard has to be adoptable everywhere to become a standard. The tradeoff accepted is that improvements made downstream need not come back. Reversal is effectively impossible once external contributions land, since relicensing would require every contributor's consent — hence a founding ADR, decided at repo creation rather than deferred. Source: governance document §1.
