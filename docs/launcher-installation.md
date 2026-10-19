# Launcher and installer contract

This maintenance design covers first-run installation, updates and doctor diagnostics.
The installer continues to install its exact recorded release from PyPI and
preserve the sole owning tool manager. It does not replace an unmanaged copy
or choose a second manager when ownership cannot be established.

## Launcher identity

Doctor compares the resolved PATH target with the running interpreter's
launcher, but executes the absolute lexical PATH entry for `--version`.
This preserves symlink shim dispatch, including
[mise shims](https://mise.jdx.dev/dev-tools/shims.html). Diagnostics name the
entry users actually invoke. Relative PATH entries and launchers inside a
project remain unexecuted. The fallback project-ancestor search stops before
the home directory or its parents; a home directory is not itself a project.
An explicit Git worktree still defines its own containment boundary.

The updater uses the same home-directory boundary when checking a manager on
PATH. It checks both the lexical entry and its resolved target for project
containment, then preserves the absolute lexical entry for the local ownership
query and the upgrade command. A symlink shim can dispatch by its invoked name;
running its resolved implementation directly can select a different command.
An accepted launcher still needs a valid installation receipt and must report
the root containing the current environment before an upgrade is offered.

## Installer admission

The uv ownership probe announces that another tool operation may hold the
lock. Each probe waits at most 15 seconds and retries a recognized lock timeout
once. Other failures stop immediately. An unresolved lock stops with retry
guidance, even when pipx is available, because it cannot establish ownership.
The timeout is local to the probe, not a persistent uv setting.

New pipx installations select an available stable Python 3.15, 3.14, 3.13, 3.12 or
3.11, in that order, and pass its verified absolute executable explicitly.
Existing pipx installations retain their own supported interpreter. Since
[pipx ignores `--python` with `--force` for an existing environment](https://github.com/pypa/pipx/blob/1.17.13/src/pipx/commands/install.py),
an unsupported or unreadable existing interpreter stops with explicit
reinstallation guidance rather than claiming it was changed. Doctor advises
when its own interpreter is outside the tested range without making that
advisory a failed connectivity check or changing package metadata.

## Validation

Controlled executable shims verify real lexical dispatch and project refusal,
including updater ownership queries from home, nested and unrelated directories.
These queries perform no package installation or upgrade.
Installer tests use fake managers and interpreters to exercise lock recovery,
unknown ownership, stable interpreter selection, existing-owner admission and
PATH shadowing without installing software or changing user configuration.
PowerShell controls exercise legacy native argument forwarding as well as the
native environment layout and PATH separator on Unix; Windows CI retains the
real supported-venv admission check. These controls preserve interpreter
validation rather than substituting a successful version response.
