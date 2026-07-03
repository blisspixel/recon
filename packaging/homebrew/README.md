# Homebrew formula for recon

`recon.rb` is a [Homebrew](https://brew.sh) formula that installs `recon-tool`
from PyPI into an isolated virtualenv and links the `recon` command. It is the
native-package-manager option for macOS / Linux; Windows users use the
`install.ps1` one-liner (a Python package is a poor fit for Scoop/winget).

## Install (users)

The tap is published at
[`blisspixel/homebrew-tap`](https://github.com/blisspixel/homebrew-tap):

```bash
brew install blisspixel/tap/recon
```

To try the formula directly from a checkout without a tap:

```bash
brew install --formula ./packaging/homebrew/recon.rb
```

Update with `brew upgrade recon`; uninstall with `brew uninstall recon`.

## The tap repository (maintainer)

The formula is published to the separate tap repo
[`blisspixel/homebrew-tap`](https://github.com/blisspixel/homebrew-tap)
as `Formula/recon.rb`. That published copy is what lets users run
`brew install blisspixel/tap/recon`. Each release, refresh the formula
here and mirror it to the tap (see below).

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
