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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;

final class RegexSecretScrubberTest extends TestCase
{
    // Credential-shaped prefixes split as constants so GitHub's secret scanner does not flag the source.
    private const string AWS = 'AKIA';

    private const string GHP = 'ghp';

    private const string GHO = 'gho';

    private const string STRIPE_LIVE = 'sk_live';

    private const string STRIPE_RK = 'rk_test';

    private const string GOOGLE = 'AIza';

    private const string JWT = 'eyJ';

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
            self::AWS.'IOSFODNN7EXAMPLE',
            '***REDACTED:aws_access_key***',
        ];
        yield 'github_personal_access_token' => [
            self::GHP.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
            '***REDACTED:github_token***',
        ];
        yield 'github_oauth_token' => [
            self::GHO.'_1234567890abcdefghijklmnopqrstuvwxyz',
            '***REDACTED:github_token***',
        ];
        yield 'stripe_live_key' => [
            self::STRIPE_LIVE.'_4eC39HqLyjWDarjtT1zdp7dc',
            '***REDACTED:stripe_key***',
        ];
        yield 'stripe_test_restricted_key' => [
            self::STRIPE_RK.'_4eC39HqLyjWDarjtT1zdp7dc',
            '***REDACTED:stripe_key***',
        ];
        yield 'slack_bot_token' => [
            'xoxb-1234567890-abcdefghij',
            '***REDACTED:slack_token***',
        ];
        yield 'google_api_key' => [
            self::GOOGLE.'SyA1234567890abcdefghijklmnopqrstuv',
            '***REDACTED:google_api_key***',
        ];
        yield 'jwt_token' => [
            self::JWT.'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
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
        yield 'database_url_connection_string' => [
            'DATABASE_URL=postgres://app_user:s3cr3tValue@db.example.com:5432/app',
            '***REDACTED:connection_uri***',
        ];
        yield 'redis_url_connection_string_without_user' => [
            'REDIS_URL=redis://:s3cr3tValue@localhost:6379',
            '***REDACTED:connection_uri***',
        ];
    }

    #[DataProvider('symfonyPlaceholderCases')]
    public function test_it_leaves_symfony_placeholder_values_unmodified(string $input): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($input, $output);
        self::assertStringNotContainsString('***REDACTED:inline_assignment***', $output);
    }

    /** @return iterable<string, array{0: string}> */
    public static function symfonyPlaceholderCases(): iterable
    {
        yield 'env_reference_in_yaml' => ["api_key: '%env(ANTHROPIC_API_KEY)%'"];
        yield 'env_reference_with_processor' => ["password: '%env(string:DB_PASSWORD)%'"];
        yield 'container_parameter_reference' => ["secret: '%kernel.secret%'"];
        yield 'shell_env_brace' => ["api_key: '\${ANTHROPIC_API_KEY}'"];
        yield 'shell_env_bare' => ["api_key: '\$ANTHROPIC_API_KEY'"];
        yield 'php_array_env_reference' => ["'api_key' => '%env(ANTHROPIC_API_KEY)%'"];
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
        $input = "STRIPE_SECRET_KEY=sk_super_secret_123\nAWS=".self::AWS."IOSFODNN7EXAMPLE\n";

        $once = $this->regexSecretScrubber->scrub($input);
        $twice = $this->regexSecretScrubber->scrub($once);

        self::assertSame($once, $twice);
    }

    public function test_multiple_secrets_in_same_input_are_all_redacted(): void
    {
        // Mix free-floating tokens (caught by their specific regex) with env-style assignments
        // (caught by env_assignment). Asserts both code paths fire in a single call.
        $input = 'Token: '.self::AWS."IOSFODNN7EXAMPLE\nGitHub: ".self::GHP."_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\nAPI_TOKEN=should_be_redacted_too\n";

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertStringNotContainsString(self::AWS.'IOSFODNN7EXAMPLE', $output);
        self::assertStringNotContainsString(self::GHP.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', $output);
        self::assertStringNotContainsString('should_be_redacted_too', $output);
        self::assertStringContainsString('***REDACTED:aws_access_key***', $output);
        self::assertStringContainsString('***REDACTED:github_token***', $output);
        self::assertStringContainsString('***REDACTED:env_assignment***', $output);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_additional_patterns_are_applied(): void
    {
        $regexSecretScrubber = new RegexSecretScrubber(additionalPatterns: ['/INTERNAL-[A-Z0-9]{12}/']);

        $output = $regexSecretScrubber->scrub('token: INTERNAL-ABC123DEF456');

        self::assertStringNotContainsString('INTERNAL-ABC123DEF456', $output);
        self::assertStringContainsString('***REDACTED:custom_0***', $output);
    }

    public function test_inline_assignment_redaction_preserves_key_and_quotes(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: "supersecretvalue"');

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    public function test_unquoted_inline_assignment_is_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: supersecretvalue');

        self::assertSame('password: ***REDACTED:inline_assignment***', $output);
    }

    public function test_unquoted_inline_assignment_leaves_symfony_placeholder_unmodified(): void
    {
        $input = 'api_key: %env(ANTHROPIC_API_KEY)%';

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($input, $output);
    }

    public function test_inline_assignment_with_an_empty_value_does_not_swallow_the_next_lines_secret(): void
    {
        $output = $this->regexSecretScrubber->scrub("password:\nsecret: hunter2ProdPassword");

        self::assertSame("password:\nsecret: ***REDACTED:inline_assignment***", $output);
    }

    public function test_unquoted_all_caps_key_value_is_only_redacted_once_by_env_assignment(): void
    {
        $output = $this->regexSecretScrubber->scrub('PASSWORD=hunter2supersecure');

        self::assertSame('PASSWORD=***REDACTED:env_assignment***', $output);
    }

    public function test_env_assignment_redaction_preserves_key_prefix(): void
    {
        $output = $this->regexSecretScrubber->scrub('STRIPE_SECRET_KEY=sk_super_secret_value');

        self::assertSame('STRIPE_SECRET_KEY=***REDACTED:env_assignment***', $output);
    }

    public function test_env_assignment_with_an_empty_value_does_not_swallow_the_next_lines_secret(): void
    {
        $output = $this->regexSecretScrubber->scrub("APP_SECRET=\nDB_PASSWORD=hunter2ProdPassword");

        self::assertSame("APP_SECRET=\nDB_PASSWORD=***REDACTED:env_assignment***", $output);
    }

    public function test_env_assignment_redacts_a_value_containing_a_literal_hash_character(): void
    {
        $output = $this->regexSecretScrubber->scrub('APP_SECRET=abc#def123whichshouldstillberedacted');

        self::assertSame('APP_SECRET=***REDACTED:env_assignment***', $output);
    }

    public function test_unquoted_inline_assignment_redacts_a_value_containing_a_literal_hash_character(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: correcthorse#batterystaple');

        self::assertSame('password: ***REDACTED:inline_assignment***', $output);
    }

    #[DataProvider('midWordCredentialKeyCases')]
    public function test_env_assignment_redacts_credential_word_anywhere_in_the_key(string $key, string $value): void
    {
        $output = $this->regexSecretScrubber->scrub(\sprintf('%s=%s', $key, $value));

        self::assertSame(\sprintf('%s=***REDACTED:env_assignment***', $key), $output);
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function midWordCredentialKeyCases(): iterable
    {
        yield 'secret_as_prefix_segment' => ['SECRET_KEY_BASE', 'zzz999aaa111'];
        yield 'password_as_middle_segment' => ['MAILER_PASSWORD_ENC', 'qwerty12345'];
        yield 'token_as_prefix_segment' => ['TOKEN_STORE', 'leakme123456'];
        yield 'key_as_middle_segment' => ['JWT_PRIVATE_KEY_PATH', '/var/secrets/jwt.pem'];
        yield 'key_as_suffix_segment_with_prefix' => ['AWS_ACCESS_KEY_ID', 'AKIAABCDEFGHEXAMPLE'];
    }

    #[DataProvider('nonCredentialKeyContainingCredentialSubstringCases')]
    public function test_env_assignment_does_not_redact_keys_containing_a_credential_word_as_a_bare_substring(string $line): void
    {
        self::assertSame($line, $this->regexSecretScrubber->scrub($line));
    }

    /** @return iterable<string, array{0: string}> */
    public static function nonCredentialKeyContainingCredentialSubstringCases(): iterable
    {
        yield 'monkey_contains_key' => ['MONKEY_COUNT=5'];
        yield 'keyspace_contains_key' => ['SESSION_KEYSPACE=xyz'];
        yield 'keyword_contains_key' => ['MY_KEYWORD_VALUE=abc'];
    }

    public function test_connection_uri_redaction_preserves_scheme_and_host(): void
    {
        $output = $this->regexSecretScrubber->scrub('DATABASE_URL=postgres://app_user:s3cr3tValue@db.internal:5432/app');

        self::assertSame('DATABASE_URL=postgres://***REDACTED:connection_uri***@db.internal:5432/app', $output);
    }

    public function test_connection_uri_redaction_covers_a_password_containing_an_at_sign(): void
    {
        $output = $this->regexSecretScrubber->scrub('DATABASE_URL=postgres://appuser:p@ssw0rd@db.example.com:5432/appdb');

        self::assertSame('DATABASE_URL=postgres://***REDACTED:connection_uri***@db.example.com:5432/appdb', $output);
    }

    public function test_google_api_key_ending_in_a_non_word_character_is_still_redacted(): void
    {
        $key = self::GOOGLE.str_repeat('a', 34).'-';
        $output = $this->regexSecretScrubber->scrub("analytics_key: {$key}\nnext_line: unrelated");

        self::assertStringNotContainsString($key, $output);
        self::assertStringContainsString('***REDACTED:google_api_key***', $output);
    }

    public function test_it_leaves_credential_free_urls_unmodified(): void
    {
        $url = 'see https://example.com:8080/docs?token=public for details';

        self::assertSame($url, $this->regexSecretScrubber->scrub($url));
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_runtime_pcre_failure_continues_to_remaining_patterns(): void
    {
        $regexSecretScrubber = new RegexSecretScrubber(additionalPatterns: [
            '/^(a+)+$/',
            '/SECONDARY-\d+/',
        ]);

        $previousLimit = \ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '50');

        try {
            $payload = str_repeat('a', 30).'b found: SECONDARY-123';
            $output = $regexSecretScrubber->scrub($payload);
        } finally {
            ini_set('pcre.backtrack_limit', false === $previousLimit ? '1000000' : $previousLimit);
        }

        self::assertStringNotContainsString('SECONDARY-123', $output);
        self::assertStringContainsString('***REDACTED:custom_1***', $output);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_invalid_additional_pattern_throws_configuration_exception(): void
    {
        $this->expectException(SecretScrubberConfigurationException::class);
        $this->expectExceptionMessage('Invalid secret-scrubbing pattern /[unterminated/');

        new RegexSecretScrubber(additionalPatterns: ['/[unterminated/']);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_empty_additional_pattern_throws_configuration_exception(): void
    {
        $this->expectException(SecretScrubberConfigurationException::class);
        $this->expectExceptionMessage('empty pattern');

        new RegexSecretScrubber(additionalPatterns: ['']);
    }

    public function test_invalid_pattern_validation_suppresses_the_internal_pcre_warning(): void
    {
        error_clear_last();

        try {
            new RegexSecretScrubber(additionalPatterns: ['/[unterminated/']);
            self::fail('expected SecretScrubberConfigurationException');
        } catch (SecretScrubberConfigurationException) {
            self::assertNull(error_get_last());
        }
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->regexSecretScrubber = new RegexSecretScrubber();
    }

    private function secretFragmentOf(string $input): string
    {
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
