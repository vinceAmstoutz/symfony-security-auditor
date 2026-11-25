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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Parameter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PulledModelNoticePass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\OllamaPulledModelList;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelNotice;

final class PulledModelNoticePassTest extends TestCase
{
    #[DataProvider('auditsOnOllama')]
    public function test_it_asks_the_ollama_server_the_audit_runs_on_about_the_configured_models(string $auditPlatformService): void
    {
        $containerBuilder = $this->containerWithOllamaAt('%env(OLLAMA_ENDPOINT)%', $auditPlatformService);

        (new PulledModelNoticePass())->process($containerBuilder);

        $definition = $containerBuilder->getDefinition(PulledModelNoticePass::SERVICE);
        $pulledModelList = $definition->getArgument(0);
        self::assertInstanceOf(Definition::class, $pulledModelList);
        $models = $definition->getArgument(2);
        self::assertInstanceOf(Parameter::class, $models);
        self::assertSame(
            [PulledModelNotice::class, OllamaPulledModelList::class, '%env(OLLAMA_ENDPOINT)%', 'symfony_security_auditor.audit.models_requiring_pricing'],
            [$definition->getClass(), $pulledModelList->getClass(), $definition->getArgument(1), (string) $models],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function auditsOnOllama(): iterable
    {
        yield 'through the platform interface' => [PlatformInterface::class];
        yield 'named directly' => ['ai.platform.ollama'];
    }

    #[DataProvider('auditsElsewhere')]
    public function test_it_asks_no_server_when_the_audit_does_not_run_on_ollama(ContainerBuilder $containerBuilder): void
    {
        (new PulledModelNoticePass())->process($containerBuilder);

        self::assertFalse($containerBuilder->hasDefinition(PulledModelNoticePass::SERVICE));
    }

    /**
     * @return iterable<string, array{ContainerBuilder}>
     */
    public static function auditsElsewhere(): iterable
    {
        $onACliAgent = self::containerWith('ai.platform.claudecode');
        $onACliAgent->register('ai.platform.ollama')->setArguments(['http://localhost:11434']);

        yield 'another platform' => [self::containerWith(PlatformInterface::class, 'ai.platform.anthropic')];
        yield 'a CLI agent beside an application platform on Ollama' => [$onACliAgent];
        yield 'no audit platform published' => [new ContainerBuilder()];
    }

    private function containerWithOllamaAt(string $endpoint, string $auditPlatformService): ContainerBuilder
    {
        $containerBuilder = self::containerWith($auditPlatformService, 'ai.platform.ollama');
        $containerBuilder->register('ai.platform.ollama')->setArguments([$endpoint, null]);

        return $containerBuilder;
    }

    private static function containerWith(string $auditPlatformService, ?string $platformInterfaceTarget = null): ContainerBuilder
    {
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->setParameter(PulledModelNoticePass::PLATFORM_SERVICE_PARAMETER, $auditPlatformService);
        if (null !== $platformInterfaceTarget) {
            $containerBuilder->setAlias(PlatformInterface::class, $platformInterfaceTarget);
        }

        return $containerBuilder;
    }
}
