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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Tooling\BcCheck;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\BcCheck\Exception\UnpatchableEnumCasesCheckException;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\BcCheck\RoaveEnumCaseAdditions;

final class RoaveEnumCaseAdditionsTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    private const string REPORTED_AS_A_BREAK = <<<'PHP'
        static function (string $caseName) use ($fromEnumName): Change {
            return Change::added('Case ' . $fromEnumName . '::' . $caseName . ' was added');
        },
        PHP;

    private const string REPORTED_WITHOUT_A_BREAK = <<<'PHP'
        static function (string $caseName) use ($fromEnumName): Change {
            return Change::added('Case ' . $fromEnumName . '::' . $caseName . ' was added', false);
        },
        PHP;

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public function test_an_added_enum_case_is_still_reported_but_no_longer_as_a_break(): void
    {
        self::assertSame(self::REPORTED_WITHOUT_A_BREAK, RoaveEnumCaseAdditions::acceptedIn(self::REPORTED_AS_A_BREAK));
    }

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public function test_the_installed_check_is_rewritten_in_place(): void
    {
        $enumCasesCheck = \sprintf('%s/enum_cases_check_%s.php', sys_get_temp_dir(), uniqid('', true));
        file_put_contents($enumCasesCheck, self::REPORTED_AS_A_BREAK);

        try {
            RoaveEnumCaseAdditions::acceptIn($enumCasesCheck);

            self::assertStringEqualsFile($enumCasesCheck, self::REPORTED_WITHOUT_A_BREAK);
        } finally {
            unlink($enumCasesCheck);
        }
    }

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public function test_a_check_that_is_not_installed_fails_the_install(): void
    {
        $this->expectException(UnpatchableEnumCasesCheckException::class);
        $this->expectExceptionMessageContaining('could not be read');

        RoaveEnumCaseAdditions::acceptIn(\sprintf('%s/missing_enum_cases_check_%s.php', sys_get_temp_dir(), uniqid('', true)));
    }

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public function test_a_check_already_patched_by_an_earlier_install_stays_as_it_is(): void
    {
        self::assertSame(self::REPORTED_WITHOUT_A_BREAK, RoaveEnumCaseAdditions::acceptedIn(self::REPORTED_WITHOUT_A_BREAK));
    }

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public function test_a_check_that_no_longer_reports_added_cases_that_way_fails_the_install(): void
    {
        $this->expectException(UnpatchableEnumCasesCheckException::class);
        $this->expectExceptionMessageContaining('does not report an added enum case the way');

        RoaveEnumCaseAdditions::acceptedIn("return Change::added('Case ' . \$name . ' appeared');");
    }
}
