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

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Detects a heredoc/nowdoc opener and its closing identifier, so the caller
 * retains the whole body verbatim instead of line-classifying it.
 */
final readonly class HeredocLineTracker
{
    private const string VALID_CLOSING_TRAILER = '[\s;,)\]]*';

    public function __construct(
        private ParenContinuationTracker $parenContinuationTracker = new ParenContinuationTracker(),
    ) {}

    public function identifierOpenedBy(string $line): ?string
    {
        if (1 !== preg_match('/<<<\s*[\'"]?([A-Za-z_]\w*)[\'"]?\s*$/', $line, $matches)) {
            return null;
        }

        return $matches[1];
    }

    /**
     * @return array{0: ?string, 1: int, 2: ?string}
     */
    public function consumeLine(string $line, string $openHeredocIdentifier, int $openParenDepth, ?string $openStringDelimiter): array
    {
        $trailer = $this->closeTrailer($line, $openHeredocIdentifier);
        if (null === $trailer) {
            return [$openHeredocIdentifier, $openParenDepth, $openStringDelimiter];
        }

        [$openParenDepth, $openStringDelimiter] = $this->parenContinuationTracker->advance(true, $trailer, $openParenDepth, $openStringDelimiter);

        return [null, $openParenDepth, $openStringDelimiter];
    }

    // Matched at line start, not column 0: PHP's flexible heredoc syntax (7.3+) allows an indented closing identifier.
    private function closeTrailer(string $line, string $identifier): ?string
    {
        if (1 !== preg_match(\sprintf('/^\s*%s(?<trailer>%s)$/', $identifier, self::VALID_CLOSING_TRAILER), $line, $matches)) {
            return null;
        }

        return $matches['trailer'];
    }
}
