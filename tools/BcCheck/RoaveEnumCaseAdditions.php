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
 * compatibility job reports a case added to an enum without counting it as a
 * break: its install rewrites the one line of roave/backward-compatibility-check
 * that counts it as one, and a removed case still fails the job.
 */
final readonly class RoaveEnumCaseAdditions
{
    private const string REPORTED_AS_A_BREAK = "' was added');";

    private const string REPORTED_WITHOUT_A_BREAK = "' was added', false);";

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

        if (1 !== substr_count($enumCasesCheck, self::REPORTED_AS_A_BREAK)) {
            throw UnpatchableEnumCasesCheckException::forUnknownReport(self::REPORTED_AS_A_BREAK);
        }

        return str_replace(self::REPORTED_AS_A_BREAK, self::REPORTED_WITHOUT_A_BREAK, $enumCasesCheck);
    }

    private static function isAlreadyAccepting(string $enumCasesCheck): bool
    {
        return 1 === substr_count($enumCasesCheck, self::REPORTED_WITHOUT_A_BREAK) && !str_contains($enumCasesCheck, self::REPORTED_AS_A_BREAK);
    }
}
