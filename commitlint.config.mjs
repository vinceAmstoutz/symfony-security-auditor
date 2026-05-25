/**
 * Commitlint configuration — enforces Conventional Commits.
 *
 * Allowed types and scopes mirror CLAUDE.md → "Commit Messages".
 * Run locally via `npx commitlint --from=origin/main --to=HEAD`.
 */
export default {
    extends: ['@commitlint/config-conventional'],
    rules: {
        'type-enum': [
            2,
            'always',
            [
                'feat',
                'fix',
                'refactor',
                'test',
                'docs',
                'chore',
                'build',
                'ci',
                'perf',
                'style',
                'revert',
            ],
        ],
        'scope-enum': [
            2,
            'always',
            [
                'agent',
                'pipeline',
                'domain',
                'llm',
                'command',
                'bundle',
                'config',
                'deps',
                'ci',
                'docs',
                'tests',
                'infrastructure',
                'advisory',
                'tool',
                'cache',
                'report',
                'scan',
                'rate-limit',
            ],
        ],
        'scope-empty': [0],
        'subject-case': [0],
        'header-max-length': [2, 'always', 100],
        'body-max-line-length': [0],
        'footer-max-line-length': [0],
    },
};
