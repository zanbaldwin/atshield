# Contributing
`atshield` is a small, solo-maintained project. Bug reports, fixes, documentation improvements, and ideas are all
genuinely welcome. Reviews can take a little while because I don't check my email every day.

New to open source? Welcome! 🥳

> By participating, you agree to uphold this project's [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Branch:** open pull requests against [`main`](https://github.com/zanbaldwin/atshield/tree/main).
- **Security issues:** please do **not** open a public issue or pull request for these. Report them privately via
  GitHub's [_report a vulnerability_](https://github.com/zanbaldwin/atshield/security/advisories/new) button. See
  [`SECURITY.md`](SECURITY.md) for the full policy.

## Reporting bugs & asking questions
Search the [existing issues](https://github.com/zanbaldwin/atshield/issues) first — it may already be known. When
opening a new one, the fastest path to a fix is to include:

- the Git commit you built from,
- the command you ran plus it's inputs (including baseline file),
- what you expected versus what actually happened.
- **NEVER** include any private keys.
  - If your issue concerns operations that require private keys, please provide a minimal example that reproduces the
    issue using `goat key generate` output.

## Pull requests
For anything substantial, feel free to open an issue first to talk it through. You may skip straight to a pull request
if you feel comfortable.

- Try to keep each pull request to one change or fix, along with the unit tests that cover it (keeps things small and
  easy to review and give feedback on).
- You deserve credit! Add your name to the list of authors in the [README](README.md), if you're comfortable.

### Running the test suite
If you're contributing, you likely already know `cargo test`. If not: pull requests are expected to pass the CI test
suite, which consists of: push, make a pull request, and let GitHub do it for you!

## A note on AI-assisted contributions
Use whatever helps you write good code (including AI). The one rule is that you understand and stand behind what you
submit: you should be able to explain what your change does and why it's correct, just as if you'd typed every line
yourself. Accountability for a contribution always rests with the human submitting it.
