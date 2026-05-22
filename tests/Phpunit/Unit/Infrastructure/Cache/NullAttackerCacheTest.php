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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Cache;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;

final class NullAttackerCacheTest extends TestCase
{
    public function test_get_always_returns_null(): void
    {
        $nullAttackerCache = new NullAttackerCache();
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];

        self::assertNull($nullAttackerCache->get($chunk));
    }

    public function test_store_is_noop_and_does_not_affect_subsequent_get(): void
    {
        $nullAttackerCache = new NullAttackerCache();
        $chunk = [ProjectFile::create('a.php', '/app/a.php', '<?php')];

        $nullAttackerCache->store($chunk, [['type' => 'sql_injection', 'severity' => 'high']]);

        self::assertNull($nullAttackerCache->get($chunk));
    }
}
