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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfiguration;

final class AuditConfigurationTest extends TestCase
{
    /**
     * @param array<string, mixed> $rawConfig
     *
     * @return array<array-key, mixed>
     */
    private function normalize(array $rawConfig): array
    {
        return (new Processor())->processConfiguration(new AuditConfiguration(), [$rawConfig]);
    }

    public function test_it_normalizes_an_empty_config_to_the_default_model(): void
    {
        self::assertSame('claude-opus-4-8', $this->normalize([])['model']);
    }

    public function test_it_applies_the_default_fail_on_threshold(): void
    {
        $audit = $this->normalize([])['audit'];
        self::assertIsArray($audit);

        self::assertSame('critical', $audit['fail_on']);
    }

    public function test_it_applies_the_default_chunking_strategy(): void
    {
        $audit = $this->normalize([])['audit'];
        self::assertIsArray($audit);
        self::assertIsArray($audit['chunking']);

        self::assertSame('feature', $audit['chunking']['strategy']);
    }

    public function test_it_applies_nested_scan_defaults(): void
    {
        $scan = $this->normalize([])['scan'];
        self::assertIsArray($scan);

        self::assertTrue($scan['respect_gitignore']);
    }

    public function test_it_preserves_an_explicit_model_override(): void
    {
        self::assertSame('gpt-5.4', $this->normalize(['model' => 'gpt-5.4'])['model']);
    }

    public function test_it_preserves_an_explicit_nested_override(): void
    {
        $audit = $this->normalize(['audit' => ['tools_enabled' => false]])['audit'];
        self::assertIsArray($audit);

        self::assertFalse($audit['tools_enabled']);
    }

    public function test_it_rejects_an_unknown_chunking_strategy(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->normalize(['audit' => ['chunking' => ['strategy' => 'nonsense']]]);
    }
}
