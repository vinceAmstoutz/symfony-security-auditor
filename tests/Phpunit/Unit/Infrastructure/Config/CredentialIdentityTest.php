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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;

final class CredentialIdentityTest extends TestCase
{
    public function test_it_reveals_only_the_leading_and_trailing_characters(): void
    {
        self::assertSame('sk-ant…qF4A', CredentialIdentity::of('sk-ant-api03-Zk1mNopQrStUvWxYz0123456789qF4A')->maskedPreview);
    }

    #[DataProvider('unpreviewableCredentials')]
    public function test_it_redacts_a_credential_it_cannot_safely_preview(string $credential): void
    {
        self::assertSame('…', CredentialIdentity::of($credential)->maskedPreview);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unpreviewableCredentials(): iterable
    {
        yield 'shorter than the preview reveals' => ['sk-ant-tooshort'];
        yield 'exactly one character below the threshold' => ['sk-ant-0123456789012345'];
        yield 'empty' => [''];
        yield 'non-ascii bytes' => ["sk-ant-\xc3\x28-0123456789abcdefghij"];
        yield 'an accidental multi-line paste' => ["sk-ant-0123456789abcdefghijkl\nsk-ant-trailing"];
        yield 'a surrounding-whitespace paste' => ['sk-ant-0123456789abcdefghijkl '];
    }

    public function test_it_previews_a_credential_of_exactly_the_minimum_length(): void
    {
        self::assertSame('sk-ant…3456', CredentialIdentity::of('sk-ant-01234567890123456')->maskedPreview);
    }

    public function test_it_fingerprints_a_credential_without_disclosing_it(): void
    {
        self::assertSame('SHA256:ed9ff73cc4b2cd57', CredentialIdentity::of('sk-ant-api03-Zk1mNopQrStUvWxYz0123456789qF4A')->fingerprint);
    }

    public function test_it_fingerprints_two_credentials_sharing_a_preview_differently(): void
    {
        $shared = CredentialIdentity::of('sk-ant-0000000000000000000qF4A')->fingerprint;

        self::assertNotSame($shared, CredentialIdentity::of('sk-ant-1111111111111111111qF4A')->fingerprint);
    }

    public function test_it_fingerprints_a_credential_it_refuses_to_preview(): void
    {
        self::assertSame('SHA256:eec67dee620cb996', CredentialIdentity::of('sk-ant-tooshort')->fingerprint);
    }
}
