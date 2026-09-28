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
use RuntimeException;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;

final readonly class UnauthorizedAuditPlatform implements PlatformInterface
{
    private ModelCatalogInterface $modelCatalog;

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
        throw new RuntimeException('HTTP 401 returned for "https://llm.example/v1/chat/completions".');
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->modelCatalog;
    }
}
