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
        self::assertSame('anthro…iews', CredentialIdentity::of('anthropic-test-key-for-previews')->maskedPreview);
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
        yield 'shorter than the preview reveals' => ['anthropic-short'];
        yield 'exactly one character below the threshold' => ['anthropic-test-key-2345'];
        yield 'empty' => [''];
        yield 'non-ascii bytes' => ["anthropic-test-key-\xc3\x28-padding"];
        yield 'an accidental multi-line paste' => ["anthropic-test-key-one\nanthropic-test-key-two"];
        yield 'a surrounding-whitespace paste' => ['anthropic-test-key-trailing '];
    }

    public function test_it_previews_a_credential_of_exactly_the_minimum_length(): void
    {
        self::assertSame('anthro…3456', CredentialIdentity::of('anthropic-test-key-23456')->maskedPreview);
    }

    public function test_it_fingerprints_a_credential_without_disclosing_it(): void
    {
        self::assertSame('SHA256:66ff24e605fe0e69', CredentialIdentity::of('anthropic-test-key-for-previews')->fingerprint);
    }

    public function test_it_fingerprints_two_credentials_sharing_a_preview_differently(): void
    {
        $shared = CredentialIdentity::of('anthropic-test-key-one-same')->fingerprint;

        self::assertNotSame($shared, CredentialIdentity::of('anthropic-test-key-two-same')->fingerprint);
    }

    public function test_it_fingerprints_a_credential_it_refuses_to_preview(): void
    {
        self::assertSame('SHA256:1e2fb7da193109ef', CredentialIdentity::of('anthropic-short')->fingerprint);
    }
}
