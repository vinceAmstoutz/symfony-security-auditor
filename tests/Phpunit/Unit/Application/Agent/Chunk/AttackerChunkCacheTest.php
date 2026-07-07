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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;

final class AttackerChunkCacheTest extends TestCase
{
    public function test_store_logs_a_warning_and_does_not_propagate_when_the_underlying_cache_throws(): void
    {
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('store')->willThrowException(new RuntimeException('disk full'));

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $attackerChunkCache = new AttackerChunkCache(
            $attackerCache,
            new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
            $logger,
        );

        $attackerChunkCache->store([], 'context', []);

        self::assertSame('Failed to write attacker cache entry', $warnings[0][0]);
    }
}
