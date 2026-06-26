# Homebrew formula for recon

`recon.rb` is a [Homebrew](https://brew.sh) formula that installs `recon-tool`
from PyPI into an isolated virtualenv and links the `recon` command. It is the
native-package-manager option for macOS / Linux; Windows users use the
`install.ps1` one-liner (a Python package is a poor fit for Scoop/winget).

## Install (users)

Once the maintainer has published the tap (see below):

```bash
brew install blisspixel/tap/recon
```

To try the formula directly from a checkout without a tap:

```bash
brew install --formula ./packaging/homebrew/recon.rb
```

Update with `brew upgrade recon`; uninstall with `brew uninstall recon`.

## Publishing the tap (maintainer)

Homebrew taps live in a separate repo named `homebrew-<tap>` (e.g.
`blisspixel/homebrew-tap`). One-time setup:

1. Create the repo `blisspixel/homebrew-tap` with a `Formula/` directory.
2. Copy `packaging/homebrew/recon.rb` to `Formula/recon.rb` there and push.

Users can then `brew install blisspixel/tap/recon`.

## Keeping it current (per release)

The formula pins only the sdist `url` and `sha256`; Homebrew derives the version
from the URL filename. After a release lands on PyPI, refresh both lines and
copy the formula to the tap:

```bash
python scripts/update_homebrew_formula.py          # rewrite url + sha256 to latest
python scripts/update_homebrew_formula.py --check   # verify it's current (gate)
```

Dependencies are deliberately not enumerated as `resource` stanzas  -  the
formula installs them from PyPI at `brew install` time. That keeps maintenance
to the single `url`/`sha256` bump above instead of dozens of pinned resources
that drift every release. (A personal tap permits this network install;
homebrew-core would not, which is why this ships as a tap, not a core formula.)
