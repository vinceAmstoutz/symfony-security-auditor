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
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;

final class OptionalModelNodeTest extends TestCase
{
    /**
     * @param array<string, mixed> $configuration
     */
    #[DataProvider('emptyModelOverrides')]
    public function test_an_empty_model_override_is_refused_with_the_message_it_always_had(array $configuration, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->process($configuration);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function emptyModelOverrides(): iterable
    {
        yield 'attacker_model' => [['attacker_model' => ''], 'Invalid configuration for path "symfony_security_auditor.attacker_model": attacker_model cannot be an empty string; omit the key or set it to null to fall back to "model".'];
        yield 'reviewer_model' => [['reviewer_model' => ''], 'Invalid configuration for path "symfony_security_auditor.reviewer_model": reviewer_model cannot be an empty string; omit the key or set it to null to fall back to "model".'];
        yield 'audit.escalation.cheap_model' => [['audit' => ['escalation' => ['cheap_model' => '']]], 'Invalid configuration for path "symfony_security_auditor.audit.escalation.cheap_model": cheap_model cannot be an empty string; omit the key or set it to null to fall back to the reviewer model.'];
    }

    public function test_a_model_override_set_to_null_falls_back_as_when_it_is_left_out(): void
    {
        $processed = $this->process(['attacker_model' => null, 'reviewer_model' => null, 'audit' => ['escalation' => ['cheap_model' => null]]]);

        self::assertSame([null, null, null], $this->modelOverrides($processed));
        self::assertSame([null, null, null], $this->modelOverrides($this->process([])));
    }

    public function test_a_model_override_keeps_the_model_it_names(): void
    {
        $processed = $this->process(['attacker_model' => 'gpt-4.1', 'reviewer_model' => 'gpt-4o-mini', 'audit' => ['escalation' => ['cheap_model' => 'gpt-4.1-nano']]]);

        self::assertSame(['gpt-4.1', 'gpt-4o-mini', 'gpt-4.1-nano'], $this->modelOverrides($processed));
    }

    /**
     * @param array<string, mixed> $configuration
     *
     * @return array<mixed>
     */
    private function process(array $configuration): array
    {
        $treeBuilder = new TreeBuilder('symfony_security_auditor');
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());

        return (new Processor())->process($treeBuilder->buildTree(), [$configuration]);
    }

    /**
     * @param array<mixed> $processed
     *
     * @return list<mixed>
     */
    private function modelOverrides(array $processed): array
    {
        $audit = $processed['audit'];
        self::assertIsArray($audit);
        $escalation = $audit['escalation'];
        self::assertIsArray($escalation);

        return [$processed['attacker_model'], $processed['reviewer_model'], $escalation['cheap_model']];
    }
}
