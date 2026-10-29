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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Test\MockPlatformFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;

final class PlatformBindingTest extends TestCase
{
    private const string NO_PLATFORM_CONFIGURED = 'No AI platform is configured. Enable a platform (e.g. "anthropic") in config/packages/ai.yaml and set its API key — the symfony/ai-bundle recipe ships with every platform commented out.';

    /**
     * @throws MissingAiPlatformException
     */
    public function test_it_hands_out_the_platform_it_is_bound_to(): void
    {
        $inMemoryPlatform = MockPlatformFactory::createPlatform('answer');

        self::assertSame($inMemoryPlatform, (new PlatformBinding($inMemoryPlatform, 'm', new NullLogger(), null, ['ai.platform.anthropic', 'ai.platform.openai']))->platform());
    }

    /**
     * @throws MissingAiPlatformException
     */
    public function test_it_says_no_platform_is_configured_when_it_is_bound_to_none_and_none_is_configured(): void
    {
        $this->expectExceptionObject(new MissingAiPlatformException(self::NO_PLATFORM_CONFIGURED));

        (new PlatformBinding(null, 'm', new NullLogger()))->platform();
    }

    /**
     * @throws MissingAiPlatformException
     */
    public function test_it_names_the_platforms_configured_and_how_to_select_one_when_it_is_bound_to_none(): void
    {
        $this->expectExceptionObject(new MissingAiPlatformException('Several AI platforms are configured (ai.platform.anthropic, ai.platform.generic.gateway) and none is selected: alias Symfony\AI\Platform\PlatformInterface to the one to audit with under "services:" in config/services.yaml, e.g. "Symfony\AI\Platform\PlatformInterface: \'@ai.platform.anthropic\'".'));

        (new PlatformBinding(null, 'm', new NullLogger(), null, ['ai.platform.anthropic', 'ai.platform.generic.gateway']))->platform();
    }
}
