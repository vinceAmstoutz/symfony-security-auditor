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
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Tells whether a file's brackets nest shallowly enough for nikic/php-parser
 * to build and walk its AST. A file a few tens of kilobytes long whose
 * brackets nest about ten thousand levels deep (`f(f(f(…)))`, `[[[…]]]`) is
 * inside the file-size cap yet crashes the process when the AST is destroyed
 * (from 10,041 nested arrays, calls or closures with an 8 MiB stack), which a
 * `catch (Throwable)` does not intercept. The bar keeps half that depth for a
 * smaller stack; PHP's own compiler refuses calls and blocks nested about
 * 4,990 deep, and real code stays far below either.
 * The depth is read from PHP's own token stream, so brackets inside string
 * literals, comments and inline HTML are not counted. Operator chains such as
 * `1+1+1+…` and `$a->b->c->…` nest the AST without nesting any bracket and
 * are not measured here. A file {@see UnmatchedClosers} says would stall PHP's
 * lexer is refused before it is tokenized at all, since that lexer takes
 * seconds on a few thousand stray closers and minutes on a few tens of
 * thousands.
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
