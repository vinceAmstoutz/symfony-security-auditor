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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

final class RegexStaticPreScannerTest extends TestCase
{
    private RegexStaticPreScanner $regexStaticPreScanner;

    #[Override]
    protected function setUp(): void
    {
        $this->regexStaticPreScanner = new RegexStaticPreScanner();
    }

    /**
     * @throws InvalidRiskMarkerException
     */
    public function test_it_returns_empty_array_when_no_files(): void
    {
        self::assertSame([], $this->regexStaticPreScanner->scan([]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_returns_empty_array_when_no_patterns_match(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Clean.php',
            '/app/src/Service/Clean.php',
            "<?php\nclass Clean { public function foo() { return 1; } }",
        );

        self::assertSame([], $this->regexStaticPreScanner->scan([$projectFile]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_unserialize_in_php_file(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Dangerous.php',
            '/app/src/Service/Dangerous.php',
            "<?php\nclass Dangerous { public function foo(\$data) { return unserialize(\$data); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('unserialize_call', $markers[0]->pattern());
        self::assertSame(2, $markers[0]->line());
        self::assertSame('src/Service/Dangerous.php', $markers[0]->filePath());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_non_constant_time_compare_regardless_of_operand_order(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Verifier.php',
            '/app/src/Service/Verifier.php',
            "<?php\nclass Verifier { public function foo(\$expectedSignature, \$input) { return \$expectedSignature === \$input; } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('hash_equals_missing', $markers[0]->pattern());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    #[DataProvider('nonConstantTimeCompareCases')]
    public function test_it_flags_non_constant_time_compare_on_canonical_variable_names(string $expression): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Verifier.php',
            '/app/src/Service/Verifier.php',
            \sprintf("<?php\nclass Verifier { public function foo(\$a, \$b) { return %s; } }", $expression),
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('hash_equals_missing', $markers[0]->pattern());
    }

    /** @return iterable<string, array{string}> */
    public static function nonConstantTimeCompareCases(): iterable
    {
        yield 'bare signature on the left' => ['$signature === $a'];
        yield 'bare hash on the left' => ['$hash === $a'];
        yield 'bare token on the right' => ['$a === $token'];
        yield 'not-identical guard' => ['$signature !== $a'];
        yield 'not-identical with suffix on the right' => ['$a !== $expectedHmac'];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_not_identical_signature_compare_in_webhook_consumer(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/PaymentWebhookConsumer.php',
            '/app/src/Webhook/PaymentWebhookConsumer.php',
            "<?php\nclass PaymentWebhookConsumer { public function consume(\$signature, \$computed) { if (\$signature !== \$computed) { throw new \RuntimeException('bad'); } } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('no_hash_equals', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_a_signature_compare_split_across_lines_with_a_leading_operator(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/PaymentWebhookConsumer.php',
            '/app/src/Webhook/PaymentWebhookConsumer.php',
            "<?php\nclass PaymentWebhookConsumer { public function consume(\$signature, \$computed) { if (\$signature\n !== \$computed) { throw new \RuntimeException('bad'); } } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('no_hash_equals', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_raw_filter_in_template(): void
    {
        $projectFile = ProjectFile::create(
            'templates/index.html.twig',
            '/app/templates/index.html.twig',
            "<h1>Hello</h1>\n{{ user.bio|raw }}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('raw_filter', $markers[0]->pattern());
        self::assertSame(2, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_groups_attribute_on_entity(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/User.php',
            '/app/src/Entity/User.php',
            "<?php\nclass User {\n    #[Groups(['user:write', 'admin:write'])]\n    private string \$role;\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('serializer_groups_attribute', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_csrf_disabled_in_form(): void
    {
        $projectFile = ProjectFile::create(
            'src/Form/UserType.php',
            '/app/src/Form/UserType.php',
            "<?php\n\$builder->add('name', null, ['csrf_protection' => false]);",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('csrf_disabled', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_hardcoded_secret_in_yaml(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/db.yaml',
            '/app/config/packages/db.yaml',
            "database:\n    password: AKIAIOSFODNN7EXAMPLEXX",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('hardcoded_secret', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_does_not_flag_env_reference_as_hardcoded_secret(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/db.yaml',
            '/app/config/packages/db.yaml',
            "database:\n    password: '%env(DATABASE_PASSWORD)%'",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertNotContains('hardcoded_secret', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_credential_assignment_in_dotenv_file(): void
    {
        $projectFile = ProjectFile::create(
            '.env',
            '/app/.env',
            "APP_ENV=prod\nAPP_SECRET=0123456789abcdef0123456789abcdef\n",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('env_credential_assignment', $markers[0]->pattern());
        self::assertSame(2, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_does_not_flag_empty_or_boilerplate_dotenv_values(): void
    {
        $projectFile = ProjectFile::create(
            '.env',
            '/app/.env',
            "APP_ENV=dev\nAPP_SECRET=\nAPP_DEBUG=1\n",
        );

        self::assertSame([], $this->regexStaticPreScanner->scan([$projectFile]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_scrubbed_secret_placeholder_in_config_file(): void
    {
        $projectFile = ProjectFile::create(
            '.env.prod',
            '/app/.env.prod',
            "MAILER_DSN=***REDACTED:connection-string***\n",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('scrubbed_secret', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_disabled_pagination_on_api_resources(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/Book.php',
            '/app/src/Entity/Book.php',
            "<?php\n#[ApiResource(paginationEnabled: false)]\nclass Book {}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('api_pagination_disabled', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_api_filters_for_review(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/Offer.php',
            '/app/src/Entity/Offer.php',
            "<?php\n#[ApiResource]\n#[ApiFilter(SearchFilter::class, properties: ['owner.email' => 'exact'])]\nclass Offer {}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('api_filter_declared', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_writable_live_props(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/Components/ProfileForm.php',
            '/app/src/Twig/Components/ProfileForm.php',
            "<?php\n#[AsLiveComponent]\nclass ProfileForm {\n    #[LiveProp(writable: true)]\n    public string \$email = '';\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('live_prop_writable', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_live_actions_for_authorization_review(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/Components/AdminPanel.php',
            '/app/src/Twig/Components/AdminPanel.php',
            "<?php\n#[AsLiveComponent]\nclass AdminPanel {\n    #[LiveAction]\n    public function deleteUser(): void {}\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('live_action_endpoint', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_shell_or_file_sinks_in_twig_extensions(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/ReportExtension.php',
            '/app/src/Twig/ReportExtension.php',
            "<?php\nclass ReportExtension extends AbstractExtension {\n    public function readFile(string \$path): string { return file_get_contents(\$path); }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('extension_shell_or_file_sink', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_bare_include_and_require_sinks_in_twig_extensions(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/TemplateExtension.php',
            '/app/src/Twig/TemplateExtension.php',
            "<?php\nclass TemplateExtension extends AbstractExtension {\n    public function renderPartial(string \$page): void { include \$page; }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('extension_shell_or_file_sink', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_does_not_flag_include_once_as_a_function_call_requiring_parens(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/BootstrapExtension.php',
            '/app/src/Twig/BootstrapExtension.php',
            "<?php\nclass BootstrapExtension extends AbstractExtension {\n    public function boot(string \$file): void { require_once \$file; }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('extension_shell_or_file_sink', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_is_safe_html_declarations_in_twig_extensions(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/MarkupExtension.php',
            '/app/src/Twig/MarkupExtension.php',
            "<?php\nclass MarkupExtension extends AbstractExtension {\n    public function getFilters(): array {\n        return [new TwigFilter('badge', [\$this, 'badge'], ['is_safe' => ['html']])];\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('extension_is_safe_html', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_voter_default_return_true(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/AdminVoter.php',
            '/app/src/Security/AdminVoter.php',
            "<?php\nclass AdminVoter { protected function voteOnAttribute() { return true; } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('voter_default_true', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_dynamic_order_by_in_repository(): void
    {
        $projectFile = ProjectFile::create(
            'src/Repository/UserRepository.php',
            '/app/src/Repository/UserRepository.php',
            "<?php\nclass UserRepository { public function find(\$order) { \$qb->orderBy(\$order); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('dynamic_order_by', $patterns);
    }

    /**
     * The idiomatic one-method-per-line Doctrine `QueryBuilder` fluent style
     * (taught in virtually every Symfony tutorial) puts `orderBy($sort)` on
     * its own line, split from the `->` on the previous line.
     *
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_dynamic_order_by_split_across_lines(): void
    {
        $projectFile = ProjectFile::create(
            'src/Repository/UserRepository.php',
            '/app/src/Repository/UserRepository.php',
            "<?php\nclass UserRepository {\n    public function find(\$sort) {\n        return \$this->createQueryBuilder('u')\n            ->orderBy(\n                \$sort\n            )\n            ->getQuery()\n            ->getResult();\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('dynamic_order_by', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    #[DataProvider('bareMailerHeaderSetterCases')]
    public function test_it_flags_bare_cc_and_bcc_mailer_header_setters(string $call): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/NotificationService.php',
            '/app/src/Service/NotificationService.php',
            "<?php\nclass NotificationService { public function send(\$email) { \$email{$call}(\$x); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('mailer_header_setter', $patterns);
    }

    /** @return iterable<string, array{string}> */
    public static function bareMailerHeaderSetterCases(): iterable
    {
        yield 'bare cc' => ['->cc'];
        yield 'bare bcc' => ['->bcc'];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    #[DataProvider('redirectWithConcatenatedInputCases')]
    public function test_it_flags_redirect_targets_built_from_a_variable_beyond_the_first_argument_character(string $argument): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/RedirectController.php',
            '/app/src/Controller/RedirectController.php',
            "<?php\nclass RedirectController { public function go(\$request) { return \$this->redirect({$argument}); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('redirect_with_input', $patterns);
    }

    /** @return iterable<string, array{string}> */
    public static function redirectWithConcatenatedInputCases(): iterable
    {
        yield 'string concatenation' => ["'http://' . \$request->query->get('host')"];
        yield 'cast before the variable' => ['(string) $request->query->get(\'url\')'];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_redirect_with_input_split_across_lines(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/RedirectController.php',
            '/app/src/Controller/RedirectController.php',
            "<?php\nclass RedirectController {\n    public function go(\$request) {\n        return \$this->redirect(\n            \$request->query->get('url')\n        );\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('redirect_with_input', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_form_submit_with_request_all_split_across_lines(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            "<?php\nclass UserController {\n    public function edit(\$request, \$form) {\n        \$form->submit(\n            \$request->request->all()\n        );\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('submit_request_all', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_a_super_admin_setter_as_a_sensitive_setter(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/User.php',
            '/app/src/Entity/User.php',
            "<?php\nclass User { public function setSuperAdmin(\$value) { \$this->superAdmin = \$value; } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('sensitive_setter', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_supports_returning_null_across_multiple_lines(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginAuthenticator.php',
            '/app/src/Security/LoginAuthenticator.php',
            "\n<?php\nclass LoginAuthenticator {\n    public function supports(Request \$request): ?bool\n    {\n        return null;\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('supports_returns_null', $markers[0]->pattern());
        self::assertSame(6, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_supports_returning_null_after_an_earlier_guard_clause(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginAuthenticator.php',
            '/app/src/Security/LoginAuthenticator.php',
            "\n<?php\nclass LoginAuthenticator {\n    public function supports(Request \$request): ?bool\n    {\n        if (!\$request->hasSession()) {\n            return false;\n        }\n\n        if (!\$request->attributes->has('_login')) {\n            return null;\n        }\n\n        return true;\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('supports_returns_null', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_http_client_request_split_across_lines(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Fetcher.php',
            '/app/src/Service/Fetcher.php',
            "\n<?php\nclass Fetcher {\n    public function __construct(private HttpClientInterface \$client) {}\n    public function fetch(string \$url) {\n        return \$this->client->request('GET', \$url);\n    }\n}",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame('http_client_request', $markers[0]->pattern());
        self::assertSame(6, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_self_validating_passport_in_authenticator(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginAuthenticator.php',
            '/app/src/Security/LoginAuthenticator.php',
            "<?php\nclass LoginAuthenticator { public function authenticate() { return new SelfValidatingPassport(new UserBadge(\$id)); } }",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('self_validating_passport', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_flags_php_serialize_in_messenger_config(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/messenger.yaml',
            '/app/config/packages/messenger.yaml',
            "framework:\n    messenger:\n        transports:\n            main:\n                serializer: php_serialize",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('php_serializer_transport', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_skips_buckets_without_patterns(): void
    {
        $projectFile = ProjectFile::create(
            'unknown.bin',
            '/app/unknown.bin',
            'unserialize() and |raw and csrf_protection: false',
        );

        self::assertSame([], $this->regexStaticPreScanner->scan([$projectFile]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_emits_multiple_markers_when_multiple_patterns_match_same_file(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Bad.php',
            '/app/src/Service/Bad.php',
            "<?php\n\$x = unserialize(\$y);\n\$z = shell_exec(\$cmd);",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('unserialize_call', $patterns);
        self::assertContains('shell_invocation', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_emits_one_marker_per_matching_line_for_the_same_pattern(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Repeated.php',
            '/app/src/Service/Repeated.php',
            "<?php\n\$a = unserialize(\$x);\n\$b = unserialize(\$y);\n\$c = unserialize(\$z);",
        );

        $markers = $this->regexStaticPreScanner->scan([$projectFile]);

        $unserializeLines = array_map(
            static fn (RiskMarker $riskMarker): int => $riskMarker->line(),
            array_values(array_filter(
                $markers,
                static fn (RiskMarker $riskMarker): bool => 'unserialize_call' === $riskMarker->pattern(),
            )),
        );

        self::assertSame([2, 3, 4], $unserializeLines);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_custom_patterns_are_merged_into_the_built_in_dictionary(): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => [
                'audit_log_missing' => [
                    'regex' => '/\$this->doPrivilegedThing\(/',
                    'description' => 'Privileged call must be followed by AuditService::log()',
                ],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'src/Service/Privileged.php',
            '/app/src/Service/Privileged.php',
            "<?php\n\$this->doPrivilegedThing();",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('audit_log_missing', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_custom_patterns_do_not_disable_the_built_in_dictionary(): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => [
                'custom_one' => ['regex' => '/CUSTOM_TOKEN/', 'description' => 'custom'],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'src/Service/Mixed.php',
            '/app/src/Service/Mixed.php',
            "<?php\nCUSTOM_TOKEN;\nunserialize(\$x);",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('custom_one', $patterns);
        self::assertContains('unserialize_call', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_custom_patterns_target_other_buckets(): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'config' => [
                'forbidden_host' => ['regex' => '/internal-admin\.example\.com/', 'description' => 'Internal host should be env-referenced'],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'config/packages/clients.yaml',
            '/app/config/packages/clients.yaml',
            "http_client:\n    base_uri: 'https://internal-admin.example.com'",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        $patterns = array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers);
        self::assertContains('forbidden_host', $patterns);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_does_not_mistake_a_pattern_ending_in_the_letter_s_for_a_dot_all_pattern(): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => [
                'literal_foos' => ['regex' => '/^foos/', 'description' => 'test'],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'src/Service/Foo.php',
            '/app/src/Service/Foo.php',
            "xfoos\nfoos",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        $literalFoosMarkers = array_values(array_filter(
            $markers,
            static fn (RiskMarker $riskMarker): bool => 'literal_foos' === $riskMarker->pattern(),
        ));
        self::assertCount(1, $literalFoosMarkers);
        self::assertSame(2, $literalFoosMarkers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_a_non_slash_delimited_pattern_without_the_dot_all_modifier_is_matched_per_line(): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => [
                'password_hash_call' => ['regex' => '~^password_hash\(.*\)~', 'description' => 'test'],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'src/Service/Hash.php',
            '/app/src/Service/Hash.php',
            "<?php\n\$x = 1;\npassword_hash(\$x);\n",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame(3, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_a_non_slash_delimited_pattern_with_the_dot_all_modifier_still_spans_lines(): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => [
                'spanning_block' => ['regex' => '~BEGIN_BLOCK.*?END_BLOCK~s', 'description' => 'test'],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'src/Service/Span.php',
            '/app/src/Service/Span.php',
            "<?php\nBEGIN_BLOCK\nmiddle content\nEND_BLOCK\n",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame(4, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    #[DataProvider('bracketDelimiterCases')]
    public function test_a_bracket_delimited_pattern_with_the_dot_all_modifier_spans_lines(string $regex): void
    {
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => [
                'spanning_block' => ['regex' => $regex, 'description' => 'test'],
            ],
        ]);
        $projectFile = ProjectFile::create(
            'src/Service/Span.php',
            '/app/src/Service/Span.php',
            "<?php\nBEGIN_BLOCK\nmiddle content\nEND_BLOCK\n",
        );

        $markers = $regexStaticPreScanner->scan([$projectFile]);

        self::assertCount(1, $markers);
        self::assertSame(4, $markers[0]->line());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function bracketDelimiterCases(): iterable
    {
        yield 'parentheses' => ['(BEGIN_BLOCK.*?END_BLOCK)s'];
        yield 'curly_braces' => ['{BEGIN_BLOCK.*?END_BLOCK}s'];
        yield 'square_brackets' => ['[BEGIN_BLOCK.*?END_BLOCK]s'];
        yield 'angle_brackets' => ['<BEGIN_BLOCK.*?END_BLOCK>s'];
    }
}
