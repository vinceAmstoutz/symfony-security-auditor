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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;

final class RegexSecretScrubberTest extends TestCase
{
    private RegexSecretScrubber $regexSecretScrubber;

    #[DataProvider('credentialPatternCases')]
    public function test_it_redacts_credential_shaped_strings(string $input, string $expectedFragment): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertStringNotContainsString($this->secretFragmentOf($input), $output);
        self::assertStringContainsString($expectedFragment, $output);
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function credentialPatternCases(): iterable
    {
        yield 'aws_access_key' => [
            'AKIA'.'IOSFODNN7EXAMPLE',
            '***REDACTED:aws_access_key***',
        ];
        yield 'github_personal_access_token' => [
            'ghp'.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
            '***REDACTED:github_token***',
        ];
        yield 'github_oauth_token' => [
            'gho'.'_1234567890abcdefghijklmnopqrstuvwxyz',
            '***REDACTED:github_token***',
        ];
        yield 'stripe_live_key' => [
            'sk_live'.'_4eC39HqLyjWDarjtT1zdp7dc',
            '***REDACTED:stripe_key***',
        ];
        yield 'stripe_test_restricted_key' => [
            'rk_test'.'_4eC39HqLyjWDarjtT1zdp7dc',
            '***REDACTED:stripe_key***',
        ];
        yield 'slack_bot_token' => [
            'xoxb-1234567890-abcdefghij',
            '***REDACTED:slack_token***',
        ];
        yield 'google_api_key' => [
            'AIza'.'SyA1234567890abcdefghijklmnopqrstuv',
            '***REDACTED:google_api_key***',
        ];
        yield 'jwt_token' => [
            'eyJ'.'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            '***REDACTED:jwt***',
        ];
        yield 'pem_private_key' => [
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxYZ\n-----END RSA PRIVATE KEY-----",
            '***REDACTED:pem_private_key***',
        ];
        yield 'env_token_assignment' => [
            'STRIPE_SECRET_KEY=sk_super_secret_value_123',
            '***REDACTED:env_assignment***',
        ];
        yield 'env_password_assignment' => [
            'DATABASE_PASSWORD=hunter2supersecure',
            '***REDACTED:env_assignment***',
        ];
        yield 'inline_password_yaml' => [
            'password: "supersecretvalue"',
            '***REDACTED:inline_assignment***',
        ];
        yield 'inline_api_key_php_array' => [
            "'api_key' => 'abcdefghij1234567890'",
            '***REDACTED:inline_assignment***',
        ];
    }

    public function test_it_leaves_non_credential_content_unmodified(): void
    {
        $code = "<?php\n\nclass UserController {\n    public function indexAction(): Response\n    {\n        return new Response('hello');\n    }\n}\n";

        self::assertSame($code, $this->regexSecretScrubber->scrub($code));
    }

    public function test_it_returns_empty_string_unmodified(): void
    {
        self::assertSame('', $this->regexSecretScrubber->scrub(''));
    }

    public function test_scrub_is_idempotent(): void
    {
        $input = "STRIPE_SECRET_KEY=sk_super_secret_123\nAWS=".'AKIA'."IOSFODNN7EXAMPLE\n";

        $once = $this->regexSecretScrubber->scrub($input);
        $twice = $this->regexSecretScrubber->scrub($once);

        self::assertSame($once, $twice);
    }

    public function test_multiple_secrets_in_same_input_are_all_redacted(): void
    {
        // Mix free-floating tokens (caught by their specific regex) with env-style assignments
        // (caught by env_assignment). Asserts both code paths fire in a single call.
        $input = 'Token: '.'AKIA'."IOSFODNN7EXAMPLE\nGitHub: ".'ghp'."_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\nAPI_TOKEN=should_be_redacted_too\n";

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertStringNotContainsString('AKIA'.'IOSFODNN7EXAMPLE', $output);
        self::assertStringNotContainsString('ghp'.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', $output);
        self::assertStringNotContainsString('should_be_redacted_too', $output);
        self::assertStringContainsString('***REDACTED:aws_access_key***', $output);
        self::assertStringContainsString('***REDACTED:github_token***', $output);
        self::assertStringContainsString('***REDACTED:env_assignment***', $output);
    }

    public function test_additional_patterns_are_applied(): void
    {
        $regexSecretScrubber = new RegexSecretScrubber(additionalPatterns: ['/INTERNAL-[A-Z0-9]{12}/']);

        $output = $regexSecretScrubber->scrub('token: INTERNAL-ABC123DEF456');

        self::assertStringNotContainsString('INTERNAL-ABC123DEF456', $output);
        self::assertStringContainsString('***REDACTED:custom_0***', $output);
    }

    public function test_invalid_additional_pattern_throws_configuration_exception(): void
    {
        $this->expectException(SecretScrubberConfigurationException::class);
        $this->expectExceptionMessage('Invalid secret-scrubbing pattern /[unterminated/');

        new RegexSecretScrubber(additionalPatterns: ['/[unterminated/']);
    }

    public function test_empty_additional_pattern_throws_configuration_exception(): void
    {
        $this->expectException(SecretScrubberConfigurationException::class);
        $this->expectExceptionMessage('empty pattern');

        new RegexSecretScrubber(additionalPatterns: ['']);
    }

    protected function setUp(): void
    {
        $this->regexSecretScrubber = new RegexSecretScrubber();
    }

    private function secretFragmentOf(string $input): string
    {
        // For env/inline assignment cases we'd otherwise need to extract just the value half;
        // but every credential case here has its raw secret appear verbatim in the input AND
        // we assert it does not appear in the scrubbed output.
        if (str_contains($input, '=')) {
            $parts = explode('=', $input, 2);

            return $parts[1] ?? $input;
        }

        if (str_contains($input, ':')) {
            $parts = explode(':', $input, 2);

            return trim($parts[1] ?? $input, ' "\'');
        }

        return $input;
    }
}
