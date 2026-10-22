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

use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CheapAttackerClientNoticePass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingLLMClient;

final class CheapAttackerClientNoticePassTest extends TestCase
{
    private const string CONFIG_NOTICES = 'symfony_security_auditor.config_notices';

    private const string EARLIER_NOTICE = 'A notice the configuration gave.';

    /**
     * @param Closure(ContainerBuilder): void $replaceClients
     */
    #[DataProvider('cheapPassLeftOnTheBundledClientCases')]
    public function test_it_notes_the_cheap_pass_still_runs_on_the_bundled_client_after_the_notices_already_given(Closure $replaceClients, string $replacedClients): void
    {
        $containerBuilder = $this->bundleContainer(escalation: true);
        $replaceClients($containerBuilder);

        (new CheapAttackerClientNoticePass())->process($containerBuilder);

        self::assertSame(
            [
                self::EARLIER_NOTICE,
                \sprintf('audit.escalation is enabled and an application client replaces %s but not security_auditor.cheap_attacker_client: the cheap first pass still runs on the bundled client, which sends the code to the symfony/ai platform with audit.escalation.cheap_model. Replace security_auditor.cheap_attacker_client as well (see docs/extending.md), or set audit.escalation.enabled: false.', $replacedClients),
            ],
            $containerBuilder->getParameter(self::CONFIG_NOTICES),
        );
    }

    /** @return iterable<string, array{Closure(ContainerBuilder): void, string}> */
    public static function cheapPassLeftOnTheBundledClientCases(): iterable
    {
        yield 'the attacker client aliased to an application client' => [
            static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->setAlias('security_auditor.attacker_client', RecordingLLMClient::class);
            },
            'security_auditor.attacker_client',
        ];
        yield 'the reviewer client aliased to an application client' => [
            static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->setAlias('security_auditor.reviewer_client', RecordingLLMClient::class);
            },
            'security_auditor.reviewer_client',
        ];
        yield 'both clients aliased to an application client' => [
            static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->setAlias('security_auditor.attacker_client', RecordingLLMClient::class);
                $containerBuilder->setAlias('security_auditor.reviewer_client', RecordingLLMClient::class);
            },
            'security_auditor.attacker_client and security_auditor.reviewer_client',
        ];
        yield 'the reviewer client redefined with an application class' => [
            static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->register('security_auditor.reviewer_client', RecordingLLMClient::class);
            },
            'security_auditor.reviewer_client',
        ];
        yield 'the reviewer client replaced and the cheap client aliased to the bundled attacker client' => [
            static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->setAlias('security_auditor.reviewer_client', RecordingLLMClient::class);
                $containerBuilder->setAlias('security_auditor.cheap_attacker_client', 'security_auditor.attacker_client');
            },
            'security_auditor.reviewer_client',
        ];
    }

    /**
     * @param Closure(ContainerBuilder): void $replaceClients
     */
    #[DataProvider('noNoticeCases')]
    public function test_it_adds_no_notice_unless_the_cheap_pass_alone_stays_on_the_bundled_client(bool $escalation, Closure $replaceClients): void
    {
        $containerBuilder = $this->bundleContainer($escalation);
        $replaceClients($containerBuilder);

        (new CheapAttackerClientNoticePass())->process($containerBuilder);

        self::assertSame([self::EARLIER_NOTICE], $containerBuilder->getParameter(self::CONFIG_NOTICES));
    }

    /** @return iterable<string, array{bool, Closure(ContainerBuilder): void}> */
    public static function noNoticeCases(): iterable
    {
        yield 'escalation off, both clients replaced' => [false, self::replaceBothClients(...)];
        yield 'escalation on, no client replaced' => [true, static function (ContainerBuilder $containerBuilder): void {}];
        yield 'escalation on, the attacker client aliased to the bundled reviewer client' => [
            true,
            static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->setAlias('security_auditor.attacker_client', 'security_auditor.reviewer_client');
            },
        ];
        yield 'escalation on, the cheap client replaced too' => [
            true,
            static function (ContainerBuilder $containerBuilder): void {
                self::replaceBothClients($containerBuilder);
                $containerBuilder->setAlias('security_auditor.cheap_attacker_client', RecordingLLMClient::class);
            },
        ];
        yield 'escalation on, the cheap client aliased to the replaced reviewer client' => [
            true,
            static function (ContainerBuilder $containerBuilder): void {
                self::replaceBothClients($containerBuilder);
                $containerBuilder->setAlias('security_auditor.cheap_attacker_client', 'security_auditor.reviewer_client');
            },
        ];
    }

    private static function replaceBothClients(ContainerBuilder $containerBuilder): void
    {
        $containerBuilder->setAlias('security_auditor.attacker_client', RecordingLLMClient::class);
        $containerBuilder->setAlias('security_auditor.reviewer_client', RecordingLLMClient::class);
    }

    /**
     * The clients and agent the bundle defines, before the application's own
     * services are merged over them.
     */
    private function bundleContainer(bool $escalation): ContainerBuilder
    {
        $containerBuilder = new ContainerBuilder();
        $containerBuilder->setParameter(self::CONFIG_NOTICES, [self::EARLIER_NOTICE]);
        $containerBuilder->register(RecordingLLMClient::class, RecordingLLMClient::class);
        $containerBuilder->register('security_auditor.attacker_client', SymfonyAiLLMClient::class);
        $containerBuilder->register('security_auditor.reviewer_client', SymfonyAiLLMClient::class);

        if ($escalation) {
            $containerBuilder->register('security_auditor.cheap_attacker_client', SymfonyAiLLMClient::class);
            $containerBuilder->register('security_auditor.cheap_attacker', AttackerAgent::class);
        }

        return $containerBuilder;
    }
}
