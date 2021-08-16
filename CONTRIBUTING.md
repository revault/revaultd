# Contributing to Revault

Anyone is welcome to contribute to Revault regardless of experience, age, or any other
concern. However, Bitcoin development (and especially vaults for that matter) requires a
high level of rigor, so it could take some time (and backs and forths) to polish a
contribution before it's ready for merge.


## Communication

Most of the communication is done on GitHub or on the `#revault` IRC channel on Libera.

Don't hesitate to open issues to ask questions or conceptually discuss a change
before going forward with the implementation if it is non-trivial.


## Looking for contributions

If you are looking for first time contributions, you can `git grep` for `FIXME`s and `TODO`s
as well as checking out the [good first issues](https://github.com/revault/revaultd/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
on the issue tracker.


# Workflow

The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests" (PRs). This
facilitates social contribution, easy testing and peer review.

In general, [commits should be atomic](https://en.wikipedia.org/wiki/Atomic_commit#Atomic_commit_convention)
and diffs should be easy to read. For this reason, do not mix any formatting
fixes or code moves with actual code changes.

When possible, make sure each individual commit is hygienic: that it builds successfully
on its own without warnings, errors, regressions, or test failures.

Commit messages should be verbose by default consisting of a short subject line,
a blank line and detailed explanatory text as separate paragraph(s), unless the
title alone is self-explanatory. Commit messages should be helpful to people
reading your code in the future, so explain the reasoning for your decisions.

If your pull request contains fixup commits (commits that change the same line of code repeatedly) or too fine-grained
commits, you may be asked to [squash](https://git-scm.com/docs/git-rebase#_interactive_mode) your commits
before it will be merged.

Patchsets should always be focused. For example, a pull request could add a
feature, fix a bug, or refactor code; but not a mixture. Please also avoid super
pull requests which attempt to do too much, are overly large, or overly complex
as this makes review difficult. Instead, prefer opening different focused pull requests.

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. PR should
be reviewed first on the conceptual level before focusing on code style or grammar
fixes.


# Code

## Minimum Supported Rust Version

`revaultd` should always compile and pass tests using **Rust 1.43**.

## Style

To avoid endless bikeshedding, just use [`rustfmt`](https://github.com/rust-lang/rustfmt).

[Clippy](https://github.com/rust-lang/rust-clippy) is also often your friend.
