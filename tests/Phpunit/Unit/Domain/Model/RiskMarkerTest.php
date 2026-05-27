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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;

final class RiskMarkerTest extends TestCase
{
    public function test_it_creates_with_valid_data(): void
    {
        $riskMarker = RiskMarker::create('src/Foo.php', 42, 'unserialize_call', 'unserialize() on payload');

        self::assertSame('src/Foo.php', $riskMarker->filePath());
        self::assertSame(42, $riskMarker->line());
        self::assertSame('unserialize_call', $riskMarker->pattern());
        self::assertSame('unserialize() on payload', $riskMarker->description());
    }

    public function test_it_throws_on_empty_file_path(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskMarker::create('  ', 1, 'pattern', 'desc');
    }

    public function test_it_throws_on_zero_line(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskMarker::create('src/Foo.php', 0, 'pattern', 'desc');
    }

    public function test_it_throws_on_negative_line(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskMarker::create('src/Foo.php', -3, 'pattern', 'desc');
    }

    public function test_it_throws_on_empty_pattern_label(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskMarker::create('src/Foo.php', 1, '  ', 'desc');
    }
}
