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
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\TokenUsage\TokenUsage;

final class ScriptedTokenUsagePlatform implements PlatformInterface
{
    /**
     * @param list<ResultInterface|RuntimeException> $results     a RuntimeException entry is thrown by that invocation
     * @param list<TokenUsage>                       $tokenUsages
     */
    public function __construct(
        private array $results,
        private array $tokenUsages,
    ) {}

    public int $invocations = 0;

    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        ++$this->invocations;
        $result = array_shift($this->results);
        $tokenUsage = array_shift($this->tokenUsages);
        if ($result instanceof RuntimeException) {
            throw $result;
        }

        if (!$result instanceof ResultInterface) {
            throw new RuntimeException('ScriptedTokenUsagePlatform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
        }

        $deferredResult = new DeferredResult(
            new PlainConverter($result),
            new InMemoryRawResult(['text' => ''], [], (object) []),
            $options,
        );
        if ($tokenUsage instanceof TokenUsage) {
            $deferredResult->getMetadata()->add('token_usage', $tokenUsage);
        }

        return $deferredResult;
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return new FallbackModelCatalog();
    }
}
