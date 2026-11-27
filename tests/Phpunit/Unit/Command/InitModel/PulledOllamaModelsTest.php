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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\InitModel;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\PulledOllamaModels;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel\TypedModelOffer;

final class PulledOllamaModelsTest extends TestCase
{
    public function test_without_a_way_to_list_pulled_models_it_asks_for_the_model_name(): void
    {
        self::assertInstanceOf(TypedModelOffer::class, (new PulledOllamaModels(null))->offer(ProviderKey::of('ollama'), 'http://localhost:11434'));
    }
}
