# SPDX-License-Identifier: Apache-2.0
"""Innsegl - non-repudiable identity and attribution for AI agents.

This distribution holds the name ``innsegl`` on PyPI for the Innsegl project.
It is a name reservation, not the implementation: Innsegl is written in Go and
lives at the module path below.

Holding the name is a security control, not housekeeping. Innsegl's product is
that an artifact's origin can be verified without trusting whoever serves it; a
distribution published under Innsegl's own name by someone else would be
exactly the attack Innsegl exists to make detectable (doc 04, asset A6, abuse
case AB-09). So this distribution is deliberately not an empty shell - it tells
whoever installs it where the real implementation is, and what a package that
is *not* ours looks like.
"""

__version__ = "0.0.2"

CANONICAL = {
    "source": "https://github.com/Raymalian/innsegl",
    "home": "https://innsegl.dev",
    "go_module": "innsegl.dev/innsegl",
    "npm_scope": "@innsegl",
    "npm_package": "innsegl",
    "license": "Apache-2.0",
}

__all__ = ["CANONICAL", "__version__", "main"]


def main() -> None:
    """Print where the real implementation lives. The console-script entry point."""
    print("Innsegl - non-repudiable identity and attribution for AI agents.")
    print()
    print("This PyPI distribution holds the name `innsegl` for the project. It is a")
    print("name reservation, not the implementation: Innsegl is written in Go.")
    print()
    print(f"  Source     {CANONICAL['source']}")
    print(f"  Home       {CANONICAL['home']}")
    print(f"  Go module  {CANONICAL['go_module']}")
    print(f"  Licence    {CANONICAL['license']}")
    print()
    print(f"The {CANONICAL['npm_scope']} npm scope and the npm package `{CANONICAL['npm_package']}` are held by")
    print("the same project. A package claiming to be Innsegl that is not linked from")
    print("the repository above is not ours - please report it:")
    print(f"  {CANONICAL['source']}/security")
