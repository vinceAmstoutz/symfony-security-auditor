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
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;

/**
 * A platform an application wires itself: it answers in one piece whatever
 * the options ask, and states its usage on the deferred result.
 */
final readonly class MetadataUsagePlatform implements PlatformInterface
{
    public function __construct(
        private string $answer,
        private int $inputTokens,
        private int $outputTokens,
    ) {}

    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult($this->answer)), new InMemoryRawResult(), $options);
        $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: $this->inputTokens, completionTokens: $this->outputTokens));

        return $deferredResult;
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return new FallbackModelCatalog();
    }
}
