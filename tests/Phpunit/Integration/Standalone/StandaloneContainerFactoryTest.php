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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

final class StandaloneContainerFactoryTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/ssa-container-'.bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->cacheDir);
    }

    #[RunInSeparateProcess]
    public function test_it_builds_a_container_exposing_a_fully_wired_audit_command(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        self::assertInstanceOf(AuditCommand::class, $containerBuilder->get(AuditCommand::class));
    }

    #[RunInSeparateProcess]
    public function test_it_aliases_the_selected_provider_when_several_are_configured(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                [],
                new StandalonePlatformConfig(
                    ['generic' => ['primary' => ['base_url' => 'http://a'], 'secondary' => ['base_url' => 'http://b']]],
                    'generic.secondary',
                ),
            ),
            $this->cacheDir,
        );

        self::assertInstanceOf(PlatformInterface::class, $containerBuilder->get(PlatformInterface::class));
    }

    #[RunInSeparateProcess]
    public function test_it_rejects_a_selector_absent_from_the_platform_block(): void
    {
        $this->expectException(UnknownPlatformProviderException::class);

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://a']]], 'mistral')),
            $this->cacheDir,
        );
    }

    #[RunInSeparateProcess]
    public function test_it_rejects_several_platforms_without_a_selector(): void
    {
        $this->expectException(AmbiguousPlatformException::class);

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                [],
                new StandalonePlatformConfig(['generic' => ['primary' => ['base_url' => 'http://a'], 'secondary' => ['base_url' => 'http://b']]]),
            ),
            $this->cacheDir,
        );
    }
}
