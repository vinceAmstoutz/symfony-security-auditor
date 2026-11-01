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
 * Asks the platform for a streamed answer, so the connection keeps receiving
 * bytes while the model generates, and hands it back read whole, as a
 * buffered call would.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StreamingPlatform implements PlatformInterface
{
    /**
     * The platforms whose bridge streams tool calls and reports the usage of
     * a streamed answer, so streaming changes neither the findings nor the
     * bill. Any other platform keeps buffered calls.
     */
    private const array STREAMED_PLATFORMS = ['anthropic'];

    public function __construct(private PlatformInterface $platform) {}

    public static function bind(PlatformBinding $platformBinding, PlatformRequestConfig $platformRequestConfig): PlatformBinding
    {
        if (!$platformRequestConfig->providerStreaming || !\in_array($platformRequestConfig->servingPlatform, self::STREAMED_PLATFORMS, true) || !$platformBinding->platform instanceof PlatformInterface) {
            return $platformBinding;
        }

        return new PlatformBinding(new self($platformBinding->platform), $platformBinding->model, $platformBinding->logger, $platformBinding->maxOutputTokens, $platformBinding->unselectedPlatforms);
    }

    #[Override]
    public function invoke(string|Model $model, array|string|object $input, array $options = []): DeferredResult
    {
        $streamedResult = $this->platform->invoke($model, $input, [...$options, 'stream' => true]);

        return new DeferredResult(new StreamedResultConverter($streamedResult), $streamedResult->getRawResult(), $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->platform->getModelCatalog();
    }
}
