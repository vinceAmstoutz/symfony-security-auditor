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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture;

use PHPUnit\Framework\TestCase;

/**
 * Expects the exception message to hold a text, as `expectExceptionMessage()`
 * did before PHPUnit 13 deprecated it, on PHPUnit 12 and 13 alike: the
 * method PHPUnit 13 replaces it with does not exist in PHPUnit 12.
 *
 * @phpstan-require-extends TestCase
 */
trait ExpectsExceptionMessageTrait
{
    protected function expectExceptionMessageContaining(string $message): void
    {
        $this->expectExceptionMessageMatches(\sprintf('/%s/', preg_quote($message, '/')));
    }
}
