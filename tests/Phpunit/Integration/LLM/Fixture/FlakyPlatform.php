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

final class FlakyPlatform implements PlatformInterface
{
    /** @var list<ResultInterface|RuntimeException> */
    private array $remaining;

    /**
     * @param list<ResultInterface|RuntimeException> $scriptedResultsOrErrors
     */
    public function __construct(array $scriptedResultsOrErrors)
    {
        $this->remaining = $scriptedResultsOrErrors;
    }

    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        $next = array_shift($this->remaining);
        if ($next instanceof RuntimeException) {
            throw $next;
        }

        if (!$next instanceof ResultInterface) {
            throw new RuntimeException('flakyPlatform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
        }

        $result = $next;

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
