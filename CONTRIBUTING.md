# Contributing to Fasmo

First off, thank you for considering contributing to Fasmo! It's people like you that make Fasmo such a great tool for the community.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Fasmo. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related bugs.

Before creating bug reports, please check this list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible. 

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Fasmo, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion and find related suggestions.

When you are creating an enhancement suggestion, please include as many details as possible.

### Your First Code Contribution

#### Local Setup

1. Fork the repository.
2. Clone your fork: `git clone https://github.com/shiyinq/fasmo.git`
3. Install dependencies:
   - Backend: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
   - Frontend: `cd frontend && npm install`
4. Set up environment variables: `cp .env.example .env` and fill in the values.
5. Run the project: `npm run dev` (from the root if configured, or in respective directories)

#### Pull Requests

The process which allows for a change to be submitted to the project:

1. Create a new branch: `git checkout -b feature/my-new-feature`
2. Make your changes and commit them: `git commit -m "feat: add some amazing feature"`
3. Push to the branch: `git push origin feature/my-new-feature`
4. Submit a Pull Request.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Python Code Style

* We use `flake8` for linting.
* Follow PEP 8 guidelines.

### Svelte/Frontend Style

* Use meaningful component names.
* Keep components small and focused.
* Use TailwindCSS for styling.

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
