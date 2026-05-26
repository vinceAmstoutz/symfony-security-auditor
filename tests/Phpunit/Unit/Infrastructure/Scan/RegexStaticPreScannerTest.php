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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

final class RegexStaticPreScannerTest extends TestCase
{
    private RegexStaticPreScanner $regexStaticPreScanner;

    protected function setUp(): void
    {
        $this->regexStaticPreScanner = new RegexStaticPreScanner();
    }

    public function test_it_returns_empty_array_when_no_files(): void
    {
        self::assertSame([], $this->regexStaticPreScanner->scan([]));
    }

    public function test_it_returns_empty_array_when_no_patterns_match(): void
    {
        $file = ProjectFile::create(
            'src/Service/Clean.php',
            '/app/src/Service/Clean.php',
            "<?php\nclass Clean { public function foo() { return 1; } }",
        );

        self::assertSame([], $this->regexStaticPreScanner->scan([$file]));
    }

    public function test_it_flags_unserialize_in_php_file(): void
    {
        $file = ProjectFile::create(
            'src/Service/Dangerous.php',
            '/app/src/Service/Dangerous.php',
            "<?php\nclass Dangerous { public function foo(\$data) { return unserialize(\$data); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        self::assertCount(1, $markers);
        self::assertSame('unserialize_call', $markers[0]->pattern());
        self::assertSame(2, $markers[0]->line());
        self::assertSame('src/Service/Dangerous.php', $markers[0]->filePath());
    }

    public function test_it_flags_raw_filter_in_template(): void
    {
        $file = ProjectFile::create(
            'templates/index.html.twig',
            '/app/templates/index.html.twig',
            "<h1>Hello</h1>\n{{ user.bio|raw }}",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        self::assertCount(1, $markers);
        self::assertSame('raw_filter', $markers[0]->pattern());
        self::assertSame(2, $markers[0]->line());
    }

    public function test_it_flags_csrf_disabled_in_form(): void
    {
        $file = ProjectFile::create(
            'src/Form/UserType.php',
            '/app/src/Form/UserType.php',
            "<?php\n\$builder->add('name', null, ['csrf_protection' => false]);",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('csrf_disabled', $patterns);
    }

    public function test_it_flags_hardcoded_secret_in_yaml(): void
    {
        $file = ProjectFile::create(
            'config/packages/db.yaml',
            '/app/config/packages/db.yaml',
            "database:\n    password: AKIAIOSFODNN7EXAMPLEXX",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('hardcoded_secret', $patterns);
    }

    public function test_it_does_not_flag_env_reference_as_hardcoded_secret(): void
    {
        $file = ProjectFile::create(
            'config/packages/db.yaml',
            '/app/config/packages/db.yaml',
            "database:\n    password: '%env(DATABASE_PASSWORD)%'",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertNotContains('hardcoded_secret', $patterns);
    }

    public function test_it_flags_voter_default_return_true(): void
    {
        $file = ProjectFile::create(
            'src/Security/AdminVoter.php',
            '/app/src/Security/AdminVoter.php',
            "<?php\nclass AdminVoter { protected function voteOnAttribute() { return true; } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('voter_default_true', $patterns);
    }

    public function test_it_flags_dynamic_order_by_in_repository(): void
    {
        $file = ProjectFile::create(
            'src/Repository/UserRepository.php',
            '/app/src/Repository/UserRepository.php',
            "<?php\nclass UserRepository { public function find(\$order) { \$qb->orderBy(\$order); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('dynamic_order_by', $patterns);
    }

    public function test_it_flags_self_validating_passport_in_authenticator(): void
    {
        $file = ProjectFile::create(
            'src/Security/LoginAuthenticator.php',
            '/app/src/Security/LoginAuthenticator.php',
            "<?php\nclass LoginAuthenticator { public function authenticate() { return new SelfValidatingPassport(new UserBadge(\$id)); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('self_validating_passport', $patterns);
    }

    public function test_it_flags_php_serialize_in_messenger_config(): void
    {
        $file = ProjectFile::create(
            'config/packages/messenger.yaml',
            '/app/config/packages/messenger.yaml',
            "framework:\n    messenger:\n        transports:\n            main:\n                serializer: php_serialize",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('php_serializer_transport', $patterns);
    }

    public function test_it_skips_buckets_without_patterns(): void
    {
        $file = ProjectFile::create(
            'unknown.bin',
            '/app/unknown.bin',
            "unserialize() and |raw and csrf_protection: false",
        );

        self::assertSame([], $this->regexStaticPreScanner->scan([$file]));
    }

    public function test_it_emits_multiple_markers_when_multiple_patterns_match_same_file(): void
    {
        $file = ProjectFile::create(
            'src/Service/Bad.php',
            '/app/src/Service/Bad.php',
            "<?php\n\$x = unserialize(\$y);\n\$z = shell_exec(\$cmd);",
        );

        $markers = $this->regexStaticPreScanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('unserialize_call', $patterns);
        self::assertContains('shell_invocation', $patterns);
    }

    public function test_custom_patterns_are_merged_into_the_built_in_dictionary(): void
    {
        $scanner = new RegexStaticPreScanner([
            'php' => [
                'audit_log_missing' => [
                    'regex' => '/\$this->doPrivilegedThing\(/',
                    'description' => 'Privileged call must be followed by AuditService::log()',
                ],
            ],
        ]);
        $file = ProjectFile::create(
            'src/Service/Privileged.php',
            '/app/src/Service/Privileged.php',
            "<?php\n\$this->doPrivilegedThing();",
        );

        $markers = $scanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('audit_log_missing', $patterns);
    }

    public function test_custom_patterns_do_not_disable_the_built_in_dictionary(): void
    {
        $scanner = new RegexStaticPreScanner([
            'php' => [
                'custom_one' => ['regex' => '/CUSTOM_TOKEN/', 'description' => 'custom'],
            ],
        ]);
        $file = ProjectFile::create(
            'src/Service/Mixed.php',
            '/app/src/Service/Mixed.php',
            "<?php\nCUSTOM_TOKEN;\nunserialize(\$x);",
        );

        $markers = $scanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('custom_one', $patterns);
        self::assertContains('unserialize_call', $patterns);
    }

    public function test_custom_patterns_target_other_buckets(): void
    {
        $scanner = new RegexStaticPreScanner([
            'config' => [
                'forbidden_host' => ['regex' => '/internal-admin\.example\.com/', 'description' => 'Internal host should be env-referenced'],
            ],
        ]);
        $file = ProjectFile::create(
            'config/packages/clients.yaml',
            '/app/config/packages/clients.yaml',
            "http_client:\n    base_uri: 'https://internal-admin.example.com'",
        );

        $markers = $scanner->scan([$file]);

        $patterns = array_map(static fn (RiskMarker $marker): string => $marker->pattern(), $markers);
        self::assertContains('forbidden_host', $patterns);
    }
}
