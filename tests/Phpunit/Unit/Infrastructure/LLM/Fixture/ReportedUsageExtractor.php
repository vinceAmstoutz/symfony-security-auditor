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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture;

use Override;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;

/**
 * Test fake: a bridge's usage extractor, which reads the raw answer and finds
 * the reported usage only when the answer carries a `usage` entry — so an
 * answer that cannot be read fails it the way it fails a real one.
 */
final readonly class ReportedUsageExtractor implements TokenUsageExtractorInterface
{
    public function __construct(
        private TokenUsage $tokenUsage,
    ) {}

    #[Override]
    public function extract(RawResultInterface $rawResult, array $options = []): ?TokenUsage
    {
        return \array_key_exists('usage', $rawResult->getData()) ? $this->tokenUsage : null;
    }
}
