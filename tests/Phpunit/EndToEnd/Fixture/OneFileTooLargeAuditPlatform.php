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
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;

/**
 * Answers as the scripted platform does, except that it refuses as too long
 * every request carrying the file that holds the marker.
 */
final readonly class OneFileTooLargeAuditPlatform implements PlatformInterface
{
    public const string TOO_LARGE_MARKER = 'SECURITY_AUDITOR_TOO_LARGE';

    private ScriptedAuditPlatform $scriptedAuditPlatform;

    public function __construct()
    {
        $this->scriptedAuditPlatform = new ScriptedAuditPlatform();
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($input instanceof MessageBag && str_contains($input->getUserMessage()?->asText() ?? '', self::TOO_LARGE_MARKER)) {
            throw new RuntimeException('prompt is too long: 250000 tokens > 200000 maximum');
        }

        return $this->scriptedAuditPlatform->invoke($model, $input, $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->scriptedAuditPlatform->getModelCatalog();
    }
}
