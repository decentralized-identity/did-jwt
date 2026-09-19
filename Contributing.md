# How to contribute to did-jwt

We love your input! We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## Report a bug with detail, background and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
    - Be specific!
    - Provide sample-code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)
- You get extra kudos if you attach a failing test demonstrating that bug

## Submitting improvements

### Commit messages

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.
Commit messages must adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

### Release process
We use [changesets](https://github.com/changesets/changesets) to automate our release process.

This automation covers versioning, changelogs and publication. Any change that should trigger a release MUST
be accompanied by a corresponding changeset file. You MUST run `pnpm changeset` to create such a file and commit it.

### Code style

Use the built-in code formatter (`npm run format`) before committing code. It makes lives much easier.

### Submitting a fix

- Branch off of `master`
- Wherever possible, commit at least one test to demonstrate the bug
- Commit your code to fix that bug
- run `pnpm changeset` to describe the fix for the release notes and commit the changeset file.
- Create a PR for it
    - Mention the issue you're fixing in the PR (Example: __Closes #17__)

### Submitting a proposal

We prefer to discuss proposals before accepting them into the codebase.
Open an issue with as much detail and background as possible to make your case.
Small proposals can come in directly as PRs, but it's generally better to discuss before starting work.

Any contributions you make will be under the Apache-2.0 License

### Posting PRs

- Describe your changes in the PR description.
- Mention issues that should be fixed or closed when the PR is merged.
- Make sure any new code has tests associated!
- Make sure the documentation is still valid if your changes get included.

Thank you for your contribution!