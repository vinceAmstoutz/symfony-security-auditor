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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnloadableBridgeTreeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\PlatformCheckErrorConverter;

final class PlatformCheckErrorConverterTest extends TestCase
{
    private const string PLATFORM_CHECK_FAILURE = 'Composer detected issues in your platform: Your Composer dependencies require a PHP version ">= 9.0.0".';

    private const string RAISING_CALL_DEPRECATION = 'Passing E_USER_ERROR to trigger_error() is deprecated since 8.4, throw an exception or call exit with a string message instead';

    /**
     * @throws UnloadableBridgeTreeException
     */
    public function test_the_error_an_older_platform_check_raises_becomes_the_exception_a_newer_one_throws(): void
    {
        $this->expectException(UnloadableBridgeTreeException::class);
        $this->expectExceptionMessage(self::PLATFORM_CHECK_FAILURE);

        (new PlatformCheckErrorConverter())(\E_USER_ERROR, self::PLATFORM_CHECK_FAILURE);
    }

    /**
     * @throws UnloadableBridgeTreeException
     */
    public function test_the_deprecation_php_raises_ahead_of_that_error_is_taken_as_part_of_it(): void
    {
        self::assertTrue((new PlatformCheckErrorConverter())(\E_DEPRECATED, self::RAISING_CALL_DEPRECATION));
    }

    /**
     * @throws UnloadableBridgeTreeException
     */
    #[DataProvider('errorsLeftToPhp')]
    public function test_every_other_error_is_left_to_php(int $severity, string $message): void
    {
        self::assertFalse((new PlatformCheckErrorConverter())($severity, $message));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function errorsLeftToPhp(): iterable
    {
        yield 'another deprecation' => [\E_DEPRECATED, 'Implicitly marking parameter $x as nullable is deprecated'];
        yield 'the same words under another severity' => [\E_USER_DEPRECATED, self::RAISING_CALL_DEPRECATION];
    }
}
