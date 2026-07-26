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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture;

use Override;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;

/**
 * A misbehaving {@see PlatformInterface} double: every turn answers with prose
 * and an unbalanced brace instead of the expected JSON array or tool call.
 * Used to prove the full container-wired pipeline degrades gracefully — a
 * finding-free, non-aborting audit — rather than crashing when a real provider
 * ignores the output contract.
 */
final class MalformedResponseAuditPlatform implements PlatformInterface
{
    private const string GARBAGE = 'I reviewed the code but here is prose, not JSON. {unbalanced';

    private readonly ModelCatalogInterface $modelCatalog;

    public function __construct()
    {
        $this->modelCatalog = new FallbackModelCatalog();
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        $inMemoryRawResult = new InMemoryRawResult(['text' => ''], [], (object) ['text' => '']);

        return new DeferredResult(new PlainConverter(new TextResult(self::GARBAGE)), $inMemoryRawResult, $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->modelCatalog;
    }
}
