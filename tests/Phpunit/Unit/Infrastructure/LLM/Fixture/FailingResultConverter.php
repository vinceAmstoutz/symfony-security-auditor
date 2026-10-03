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
use RuntimeException;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\ResultConverterInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;

/**
 * Test fake: a bridge converter that fails on every answer it is handed, the
 * way a real one does when the raw answer holds something it cannot turn into
 * a result.
 */
final readonly class FailingResultConverter implements ResultConverterInterface
{
    public function __construct(
        private RuntimeException $runtimeException,
        private ?TokenUsageExtractorInterface $tokenUsageExtractor = null,
    ) {}

    #[Override]
    public function supports(Model $model): bool
    {
        return true;
    }

    #[Override]
    public function convert(RawResultInterface $result, array $options = []): ResultInterface
    {
        throw $this->runtimeException;
    }

    #[Override]
    public function getTokenUsageExtractor(): ?TokenUsageExtractorInterface
    {
        return $this->tokenUsageExtractor;
    }
}
