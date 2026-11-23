<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 *
 * Tells whether a file's brackets nest shallowly enough for nikic/php-parser:
 * freeing the AST of brackets nested about 10,000 deep crashes PHP, past any
 * `catch`. Brackets in strings, comments and inline HTML do not count. Refuses
 * a file {@see UnmatchedClosers} says would stall PHP's lexer before
 * tokenizing it.
 */
final readonly class NestingDepthGuard
{
    public const int MAX_NESTING_DEPTH = 5000;

    private const array OPENERS = ['(', '[', '{', \T_CURLY_OPEN, \T_DOLLAR_OPEN_CURLY_BRACES, \T_ATTRIBUTE];

    private const array CLOSERS = [')', ']', '}'];

    public function __construct(
        private LoggerInterface $logger = new NullLogger(),
    ) {}

    public function admits(ProjectFile $projectFile): bool
    {
        if (UnmatchedClosers::exceedLimit($projectFile->content())) {
            $this->logger->warning('Skipping a file holding too many unmatched closing brackets to tokenize safely', [
                'file' => $projectFile->relativePath(),
                'max_unmatched_closers' => UnmatchedClosers::LIMIT,
            ]);

            return false;
        }

        if (!$this->nestsTooDeeply($projectFile->content())) {
            return true;
        }

        $this->logger->warning('Skipping a file whose brackets nest too deeply to parse safely', [
            'file' => $projectFile->relativePath(),
            'max_nesting_depth' => self::MAX_NESTING_DEPTH,
        ]);

        return false;
    }

    private function nestsTooDeeply(string $source): bool
    {
        $depth = 0;
        foreach (token_get_all($source) as $token) {
            $depth += $this->depthChange(\is_array($token) ? $token[0] : $token);
            if ($depth > self::MAX_NESTING_DEPTH) {
                return true;
            }
        }

        return false;
    }

    private function depthChange(int|string $token): int
    {
        return match (true) {
            \in_array($token, self::OPENERS, true) => 1,
            \in_array($token, self::CLOSERS, true) => -1,
            default => 0,
        };
    }
}
