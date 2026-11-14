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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\BcCheck;

use VinceAmstoutz\SymfonySecurityAuditor\Tooling\BcCheck\Exception\UnpatchableEnumCasesCheckException;

/**
 * docs/versioning.md lets an enum gain cases in a MINOR release, so the API
 * compatibility job no longer fails on a case added to an enum: its install
 * removes, from the changes the enum cases check of
 * roave/backward-compatibility-check returns, the one line that adds the
 * added cases, and a removed case still fails the job.
 */
final readonly class RoaveEnumCaseAdditions
{
    private const string ADDED_CASES_RETURNED = '/^[ \t]*\.\.\.\$caseAddedChanges,\R/m';

    private const string ADDED_CASES_COMPUTED = '$caseAddedChanges = ';

    private const string INSTALLED_ENUM_CASES_CHECK = '/var/bc-check/vendor/roave/backward-compatibility-check/src/DetectChanges/BCBreak/ClassBased/EnumCasesChanged.php';

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public static function acceptInInstalledRoave(): void
    {
        self::acceptIn(\dirname(__DIR__, 2).self::INSTALLED_ENUM_CASES_CHECK);
    }

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public static function acceptIn(string $enumCasesCheckPath): void
    {
        $enumCasesCheck = is_file($enumCasesCheckPath) ? file_get_contents($enumCasesCheckPath) : false;
        if (false === $enumCasesCheck) {
            throw UnpatchableEnumCasesCheckException::forUnreadableCheck($enumCasesCheckPath);
        }

        file_put_contents($enumCasesCheckPath, self::acceptedIn($enumCasesCheck));
    }

    /**
     * @throws UnpatchableEnumCasesCheckException
     */
    public static function acceptedIn(string $enumCasesCheck): string
    {
        if (self::isAlreadyAccepting($enumCasesCheck)) {
            return $enumCasesCheck;
        }

        if (1 !== preg_match_all(self::ADDED_CASES_RETURNED, $enumCasesCheck)) {
            throw UnpatchableEnumCasesCheckException::forUnknownReport('...$caseAddedChanges,');
        }

        return preg_replace(self::ADDED_CASES_RETURNED, '', $enumCasesCheck) ?? throw UnpatchableEnumCasesCheckException::forUnknownReport('...$caseAddedChanges,');
    }

    private static function isAlreadyAccepting(string $enumCasesCheck): bool
    {
        return 0 === preg_match_all(self::ADDED_CASES_RETURNED, $enumCasesCheck) && str_contains($enumCasesCheck, self::ADDED_CASES_COMPUTED);
    }
}
