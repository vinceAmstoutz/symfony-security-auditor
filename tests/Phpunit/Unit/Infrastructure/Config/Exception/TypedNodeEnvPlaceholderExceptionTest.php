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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config\Exception;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\TypedNodeEnvPlaceholderException;

final class TypedNodeEnvPlaceholderExceptionTest extends TestCase
{
    public function test_it_names_the_setting_and_asks_for_a_literal_value(): void
    {
        $typedNodeEnvPlaceholderException = TypedNodeEnvPlaceholderException::forPaths(['symfony_security_auditor.audit.min_score']);

        self::assertSame(
            'Invalid configuration for path "symfony_security_auditor.audit.min_score": an environment variable placeholder ("%env(...)%") is not supported on this setting, which the bundle reads while the container is built, before the variable has a value. Set a literal value instead.',
            $typedNodeEnvPlaceholderException->getMessage(),
        );
    }

    public function test_it_names_every_setting_in_the_order_given(): void
    {
        $typedNodeEnvPlaceholderException = TypedNodeEnvPlaceholderException::forPaths(['symfony_security_auditor.cache.enabled', 'symfony_security_auditor.audit.fail_on']);

        self::assertStringStartsWith('Invalid configuration for path "symfony_security_auditor.cache.enabled", "symfony_security_auditor.audit.fail_on": an environment', $typedNodeEnvPlaceholderException->getMessage());
    }
}
