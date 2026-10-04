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
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;

/**
 * Test fake: hands back the scripted deferred results in order — so a test
 * decides what each one wraps and when it fails — and throws a scripted
 * exception at dispatch time.
 */
final class ScriptedDeferredPlatform implements PlatformInterface
{
    public int $invocations = 0;

    /**
     * @param list<DeferredResult|RuntimeException> $results a RuntimeException entry is thrown by that invocation
     */
    public function __construct(
        private array $results,
    ) {}

    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        ++$this->invocations;
        $result = array_shift($this->results);
        if ($result instanceof RuntimeException) {
            throw $result;
        }

        if (!$result instanceof DeferredResult) {
            throw new RuntimeException('ScriptedDeferredPlatform invoked more times than scripted.');
        }

        return $result;
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return new FallbackModelCatalog();
    }
}
