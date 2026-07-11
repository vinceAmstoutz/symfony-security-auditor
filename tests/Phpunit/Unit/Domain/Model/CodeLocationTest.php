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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;

final class CodeLocationTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     */
    public function test_a_whitespace_only_file_path_is_rejected_as_blank(): void
    {
        $this->expectException(InvalidCodeLocationException::class);

        new CodeLocation('   ', 1, 1);
    }
}
