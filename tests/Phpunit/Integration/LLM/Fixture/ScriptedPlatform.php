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
use RuntimeException;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ResultInterface;

final class ScriptedPlatform implements PlatformInterface
{
    /** @var list<ResultInterface> */
    private array $remaining;

    /**
     * @param list<ResultInterface> $scriptedResults
     */
    public function __construct(
        array $scriptedResults,
        private readonly ?PlatformInvocationLog $platformInvocationLog = null,
    ) {
        $this->remaining = $scriptedResults;
    }

    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($this->platformInvocationLog instanceof PlatformInvocationLog) {
            ++$this->platformInvocationLog->invocations;
            if ($input instanceof MessageBag) {
                $this->platformInvocationLog->messageSnapshots[] = $input->getMessages();
            }
        }

        $result = array_shift($this->remaining);
        if (!$result instanceof ResultInterface) {
            throw new RuntimeException('scriptedPlatform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
        }

        return new DeferredResult(
            new PlainConverter($result),
            new InMemoryRawResult(['text' => ''], [], (object) []),
            $options,
        );
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return new FallbackModelCatalog();
    }
}
