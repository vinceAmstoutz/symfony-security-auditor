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
use stdClass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneConsoleCommandFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

final class StandaloneConsoleCommandFactoryTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/ssa-cmd-'.bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->cacheDir);
    }

    #[RunInSeparateProcess]
    public function test_it_wraps_the_invokable_audit_command_under_its_name_and_alias(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        $command = (new StandaloneConsoleCommandFactory())->create($containerBuilder);

        self::assertSame('audit:run', $command->getName());
        self::assertContains('audit', $command->getAliases());
    }

    public function test_it_rejects_a_container_whose_audit_service_is_not_the_audit_command(): void
    {
        $this->expectException(UnresolvableAuditCommandException::class);

        $containerBuilder = new ContainerBuilder();
        $containerBuilder->register(AuditCommand::class, stdClass::class)->setPublic(true);
        $containerBuilder->compile();

        (new StandaloneConsoleCommandFactory())->create($containerBuilder);
    }
}
