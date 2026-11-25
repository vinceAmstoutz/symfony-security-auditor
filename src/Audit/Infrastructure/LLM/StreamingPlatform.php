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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Override;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;

/**
 * Asks the platform for a streamed answer, so an idle connection is never
 * cut, then returns it read whole, as a buffered call would. A platform the
 * run cannot name keeps buffered calls.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StreamingPlatform implements PlatformInterface
{
    /**
     * Bridges that mishandle a stream in symfony/ai 0.15: Vertex AI and Venice
     * add up running usage totals, Cohere and MiniMax report no usage and
     * Bedrock's native routes do not stream.
     */
    private const array BUFFERED_PLATFORMS = ['vertexai', 'venice', 'cohere', 'minimax', 'bedrock'];

    /**
     * Their API reports a stream's usage only when asked, which their bridge
     * does not do.
     */
    private const array USAGE_REQUESTING_PLATFORMS = ['deepseek', 'mistral'];

    private const array USAGE_REQUEST = ['stream_options' => ['include_usage' => true]];

    /**
     * @param array<string, mixed> $streamOptions what a streamed call adds to its options
     */
    public function __construct(
        private PlatformInterface $platform,
        private StreamMetering $streamMetering = new StreamMetering(),
        private array $streamOptions = [],
    ) {}

    public static function bind(PlatformBinding $platformBinding, PlatformRequestConfig $platformRequestConfig): PlatformBinding
    {
        if (!$platformRequestConfig->streaming || !self::streams($platformRequestConfig->servingPlatform) || !$platformBinding->platform instanceof PlatformInterface) {
            return $platformBinding;
        }

        $streamOptions = \in_array($platformRequestConfig->servingPlatform, self::USAGE_REQUESTING_PLATFORMS, true) ? self::USAGE_REQUEST : [];

        return new PlatformBinding(new self($platformBinding->platform, streamOptions: $streamOptions), $platformBinding->model, $platformBinding->logger, $platformBinding->maxOutputTokens, $platformBinding->unselectedPlatforms);
    }

    private static function streams(?string $servingPlatform): bool
    {
        return null !== $servingPlatform && !\in_array($servingPlatform, self::BUFFERED_PLATFORMS, true);
    }

    #[Override]
    public function invoke(string|Model $model, array|string|object $input, array $options = []): DeferredResult
    {
        if (!$this->streamMetering->isMetered()) {
            return $this->platform->invoke($model, $input, $options);
        }

        $streamedResult = $this->platform->invoke($model, $input, [...$options, ...$this->streamOptions, 'stream' => true]);

        $bufferedResend = new BufferedResend(fn (): DeferredResult => $this->platform->invoke($model, $input, $options));

        return new DeferredResult(new StreamedResultConverter($streamedResult, $this->streamMetering, $bufferedResend), $streamedResult->getRawResult(), $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->platform->getModelCatalog();
    }
}
