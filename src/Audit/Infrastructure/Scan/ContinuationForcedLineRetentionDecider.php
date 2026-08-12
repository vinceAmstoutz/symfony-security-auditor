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

use Override;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Decorates a {@see LineRetentionDeciderInterface}: retains a line that
 * continues an open construct regardless of the wrapped decider's verdict.
 */
final readonly class ContinuationForcedLineRetentionDecider implements LineRetentionDeciderInterface
{
    public function __construct(
        private LineRetentionDeciderInterface $lineRetentionDecider,
    ) {}

    #[Override]
    public function isRetained(string $line, LineRetentionContext $lineRetentionContext): bool
    {
        if ($lineRetentionContext->openParenDepth > 0 || $lineRetentionContext->opensHeredoc) {
            return true;
        }

        return $this->lineRetentionDecider->isRetained($line, $lineRetentionContext);
    }
}
