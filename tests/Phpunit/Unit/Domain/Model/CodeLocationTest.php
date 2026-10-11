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

    /**
     * @throws InvalidCodeLocationException
     */
    public function test_the_echoed_file_path_is_the_file_path_when_no_other_spelling_is_given(): void
    {
        self::assertSame('src/A.php', (new CodeLocation('src/A.php', 1, 1))->echoedFilePath());
    }

    /**
     * @throws InvalidCodeLocationException
     */
    public function test_the_echoed_file_path_is_the_spelling_the_model_wrote(): void
    {
        $codeLocation = new CodeLocation('src/A.php', 1, 1, './src/A.php');

        self::assertSame('src/A.php', $codeLocation->filePath());
        self::assertSame('./src/A.php', $codeLocation->echoedFilePath());
    }
}
