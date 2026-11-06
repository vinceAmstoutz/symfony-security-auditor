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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Fixture;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;

final class ExpectsExceptionMessageTraitTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    public function test_it_expects_a_message_holding_the_given_text_as_written(): void
    {
        $this->expectExceptionMessageContaining('File "a/b.php" (line 3) [x]? *.');

        throw new RuntimeException('Refused: File "a/b.php" (line 3) [x]? *. Nothing was read.');
    }
}
