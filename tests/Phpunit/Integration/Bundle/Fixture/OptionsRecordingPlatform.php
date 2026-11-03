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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture;

use Override;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\Bridge\StubAnswerPlatform;

/**
 * Test fake: a platform the container builds on its own, which keeps the
 * options of the last call it was handed so a test can read what the wired
 * client sent.
 */
final class OptionsRecordingPlatform implements PlatformInterface
{
    /** @var array<string, mixed> */
    public static array $lastOptions = [];

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        self::$lastOptions = $options;

        return StubAnswerPlatform::answering('[]')->invoke($model, $input, $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return new FallbackModelCatalog();
    }
}
