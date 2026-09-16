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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\NullCredentialStore;

final class NullCredentialStoreTest extends TestCase
{
    public function test_it_has_no_credential_to_read_back(): void
    {
        self::assertNull((new NullCredentialStore())->read('ANTHROPIC_API_KEY'));
    }

    public function test_it_has_nothing_to_remove(): void
    {
        self::assertFalse((new NullCredentialStore())->remove('ANTHROPIC_API_KEY'));
    }

    public function test_it_keeps_credentials_nowhere(): void
    {
        self::assertNull((new NullCredentialStore())->location());
    }

    public function test_it_refuses_to_pretend_it_stored_a_credential(): void
    {
        $this->expectException(CredentialStoreWriteException::class);
        $this->expectExceptionMessage('No per-user configuration directory could be resolved');

        (new NullCredentialStore())->write('ANTHROPIC_API_KEY', 'anthropic-test-key-nowhere');
    }
}
