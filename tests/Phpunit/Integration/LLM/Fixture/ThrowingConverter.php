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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\ResultConverterInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;
use Throwable;

final class ThrowingConverter implements ResultConverterInterface
{
    public function __construct(
        private readonly Throwable $throwable,
        private readonly ?TokenUsageExtractorInterface $tokenUsageExtractor = null,
    ) {}

    #[Override]
    public function supports(Model $model): bool
    {
        return true;
    }

    #[Override]
    public function convert(RawResultInterface $result, array $options = []): ResultInterface
    {
        throw $this->throwable;
    }

    #[Override]
    public function getTokenUsageExtractor(): ?TokenUsageExtractorInterface
    {
        return $this->tokenUsageExtractor;
    }
}
