# ADR-0070: Build the images once; the host deploys a bundle only for the commit it verified

- Status: accepted
- Date: 2026-10-04
- Deciders: the operator

## Context

`make update` on a deployment host builds the stack's three images: the
runtime, the api image (the runtime plus the built dashboard), and the
backup image. That build includes a full dashboard build, and on a small
host it is the slowest part of an update by far.

The images can be built on another machine instead. The Dockerfile already
cross-compiles: its build stages run on the build machine's platform and
target the host's. No registry is used, so the images have to reach the host
another way, and the host has to be able to tell that what arrived is what it
would have built itself.

The host's existing gate (`scripts/innsegl-update.sh`) verifies the source:
it fast-forwards `main` only through merge commits whose children carry a
verified signature. That gate says nothing about an image built elsewhere.

## Decision

1. **One file per deploy.** `make image-bundle` builds the three images for
   the host's platform (`INNSEGL_IMAGE_PLATFORM`, default `linux/amd64`),
   saves them into `dist/innsegl-images-<commit>-<os>-<arch>.tar.gz`, and
   writes a `.sha256` beside it. It refuses a working tree with a tracked
   change, or an untracked file under any image's inputs. It prints the copy
   command with the host as a placeholder.
2. **Every image names the commit of every input.** Each image carries the
   last commit that touched what it is built from: `dev.innsegl.commit` for
   the Go inputs on the runtime and api images, `dev.innsegl.ui-commit` for
   `web/` on the api image, and `dev.innsegl.commit` for the Dockerfile on
   the backup image, whose stage copies nothing else. The Makefile computes
   these from git for a host build and for a bundle alike. A value is never a
   dirty one: a bundle is not made from, or accepted for, a dirty tree.
3. **The host checks before it uses.** `innsegl-here-services`, which
   `make update` runs, looks for the bundle for its own commit and platform,
   or the one `INNSEGL_IMAGE_BUNDLE` names. When there is one it:
   - checks the file against its `.sha256`;
   - loads it under staging tags, separate from the images that are running;
   - requires exactly the three staging images, each for the host's
     platform, each label equal to the value the host computes from its own
     checkout;
   - only then retags them to the names compose runs.
   Any failure refuses the update and starts nothing. It never falls back to
   a build: a host that quietly built something else is what this rules out.
4. **No bundle, no change.** Without a bundle the host builds as before, so a
   fresh host needs nothing from another machine. A bundle for another commit
   is reported and ignored.
5. **The start never builds.** After the images are loaded or built, the
   start runs with `--no-build`.
6. **The checks before a deploy are unchanged.** The update gate,
   the skip when the deployed commit is current and the core is running, and
   the record of the deployed commit work exactly as before.

### The trust model, stated plainly

- The **source** is verified by the existing gate, as before.
- The **image** is bound to that source by its labels: the host accepts it
  only if it says it was built from the inputs of the commit the host has
  verified. The label is written by the machine that built the image. It
  attests what that machine says it built, not a reproducible build that the
  host repeats.
- The **checksum** catches a truncated or corrupted copy. It travels with the
  bundle, so it does not authenticate it.
- The **file** travels over the operator's own authenticated SSH session to
  the host. Authenticity rests on that channel and on the build machine being
  the operator's own; anyone who can write the host's checkout can already
  change what it builds.

## Alternatives considered

- **A registry.** It would need running, securing and authenticating to, for
  a deployment with one host and one operator. Not taken.
- **Keep building on the host.** Correct, but slow. It stays as the fallback
  for a host with no bundle.
- **Label every image with HEAD.** Every commit, a README change too, would
  make new images and restart every service. The per-input commit keeps an
  unchanged image unchanged.
- **Sign the bundle.** It would authenticate the file apart from the channel.
  The operator's SSH session already does that for a single operator. Signing
  is the step to add if bundles ever come from somewhere else.
- **Fall back to a build when a bundle fails its checks.** It hides the
  failure. A refusal says something is wrong.

## Consequences

- An update on the host loads and retags images instead of building them.
  What restarts is still only what changed: an unchanged image keeps its ID.
- The bundle carries its base layers, so each deploy copies the three
  images in full, compressed.
- The bundle must be built from the commit the host deploys. One built before
  a merge has a different commit in its file name, and the host ignores it
  and builds.
- `docker load` applies the names in the file before the checks run. A bundle
  that carries a name other than the three staging tags is refused, but by
  then it may have moved that name. Nothing is started, and the next build or
  verified load replaces it.
- The build stage installs gitsign without `GOBIN`. `go install` refuses to
  cross-compile into one, so a build for another platform failed before this.
