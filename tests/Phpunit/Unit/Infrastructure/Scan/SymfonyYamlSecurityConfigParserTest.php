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
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class SymfonyYamlSecurityConfigParserTest extends TestCase
{
    private SymfonyYamlSecurityConfigParser $symfonyYamlSecurityConfigParser;

    #[Override]
    protected function setUp(): void
    {
        $this->symfonyYamlSecurityConfigParser = new SymfonyYamlSecurityConfigParser();
    }

    public function test_a_document_with_numeric_top_level_keys_is_ignored_instead_of_crashing(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            1:
                question: Example question

            2:
                question: Another question
            YAML);

        self::assertSame([], $accessControl);
    }

    public function test_it_parses_scalar_roles(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/admin, roles: ROLE_ADMIN }
            YAML);

        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $accessControl);
    }

    public function test_it_parses_list_form_roles(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/admin
                      roles: [ROLE_ADMIN, ROLE_SUPER_ADMIN]
            YAML);

        self::assertSame(['^/admin' => ['ROLE_ADMIN', 'ROLE_SUPER_ADMIN']], $accessControl);
    }

    public function test_two_rules_for_the_same_path_keep_first_match_precedence_instead_of_last_wins(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/api/orders, methods: [GET], roles: PUBLIC_ACCESS }
                    - { path: ^/api/orders, methods: [POST], roles: ROLE_ADMIN }
            YAML);

        self::assertSame(
            ['^/api/orders' => ['PUBLIC_ACCESS', 'methods: GET', 'or: ROLE_ADMIN, methods: POST']],
            $accessControl,
        );
    }

    public function test_an_explicitly_empty_roles_rule_is_recorded_as_public_instead_of_dropped(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/status, roles: [] }
            YAML);

        self::assertSame(['^/status' => ['PUBLIC']], $accessControl);
    }

    public function test_a_later_rule_for_a_publicly_matched_path_does_not_override_first_match(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/status, roles: [] }
                    - { path: ^/status, roles: ROLE_ADMIN }
            YAML);

        self::assertSame(['^/status' => ['PUBLIC', 'or: ROLE_ADMIN']], $accessControl);
    }

    public function test_a_public_rule_after_a_restricted_rule_for_the_same_path_is_appended_as_or(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/status, methods: [POST], roles: ROLE_ADMIN }
                    - { path: ^/status, methods: [GET], roles: [] }
            YAML);

        self::assertSame(
            ['^/status' => ['ROLE_ADMIN', 'methods: POST', 'or: methods: GET']],
            $accessControl,
        );
    }

    public function test_a_fully_public_rule_after_a_restricted_rule_for_the_same_path_is_appended_as_or_public(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/reports, methods: [POST], roles: ROLE_ADMIN }
                    - { path: ^/reports, roles: [] }
            YAML);

        self::assertSame(
            ['^/reports' => ['ROLE_ADMIN', 'methods: POST', 'or: PUBLIC']],
            $accessControl,
        );
    }

    public function test_a_path_after_a_merged_duplicate_is_still_processed(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/api/orders, methods: [GET], roles: PUBLIC_ACCESS }
                    - { path: ^/api/orders, methods: [POST], roles: ROLE_ADMIN }
                    - { path: ^/admin, roles: ROLE_ADMIN }
            YAML);

        self::assertArrayHasKey('^/admin', $accessControl);
        self::assertSame(['ROLE_ADMIN'], $accessControl['^/admin']);
    }

    public function test_merging_a_later_duplicate_retains_earlier_recorded_paths(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/admin, roles: ROLE_ADMIN }
                    - { path: ^/api, roles: ROLE_USER }
                    - { path: ^/admin, roles: ROLE_SUPER }
            YAML);

        self::assertSame(
            ['^/admin' => ['ROLE_ADMIN', 'or: ROLE_SUPER'], '^/api' => ['ROLE_USER']],
            $accessControl,
        );
    }

    public function test_it_surfaces_allow_if_expressions(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/api
                      allow_if: "'127.0.0.1' == request.getClientIp() or is_granted('ROLE_API')"
            YAML);

        self::assertSame(
            ['^/api' => ["allow_if: '127.0.0.1' == request.getClientIp() or is_granted('ROLE_API')"]],
            $accessControl,
        );
    }

    public function test_it_surfaces_methods_ips_and_channel_constraints(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/internal
                      roles: ROLE_OPS
                      methods: [POST, DELETE]
                      ips: [127.0.0.1, 10.0.0.0/8]
                      requires_channel: https
            YAML);

        self::assertSame(
            ['^/internal' => ['ROLE_OPS', 'methods: POST|DELETE', 'ips: 127.0.0.1, 10.0.0.0/8', 'requires_channel: https']],
            $accessControl,
        );
    }

    /**
     * Symfony's own route/request matching uppercases HTTP methods
     * internally, so `methods: [post]` and `methods: [POST]` are equally
     * valid, semantically-identical YAML. The `methods: ...` marker must be
     * normalized to uppercase here, since
     * `SymfonyMappingContextRenderer::alternativeCoversMethods()` re-parses
     * it with an uppercase-only regex to decide route coverage.
     */
    public function test_it_normalizes_lowercase_methods_to_uppercase(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/admin
                      roles: ROLE_ADMIN
                      methods: [post, delete]
            YAML);

        self::assertSame(
            ['^/admin' => ['ROLE_ADMIN', 'methods: POST|DELETE']],
            $accessControl,
        );
    }

    public function test_it_surfaces_a_host_constraint_alongside_roles(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/admin
                      roles: ROLE_USER_HOST
                      host: symfony\.com$
            YAML);

        self::assertSame(
            ['^/admin' => ['ROLE_USER_HOST', 'host: symfony\.com$']],
            $accessControl,
        );
    }

    public function test_it_records_a_host_only_access_control_entry_instead_of_dropping_it(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/internal-admin
                      host: admin\.internal\.example\.com
            YAML);

        self::assertSame(
            ['^/internal-admin' => ['host: admin\.internal\.example\.com']],
            $accessControl,
        );
    }

    public function test_it_surfaces_a_port_constraint(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - path: ^/admin
                      roles: ROLE_ADMIN
                      port: 8000
            YAML);

        self::assertSame(
            ['^/admin' => ['ROLE_ADMIN', 'port: 8000']],
            $accessControl,
        );
    }

    public function test_it_reads_access_control_inside_when_env_blocks(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            when@prod:
                security:
                    access_control:
                        - { path: ^/metrics, roles: ROLE_MONITOR }
            YAML);

        self::assertSame(['^/metrics' => ['ROLE_MONITOR']], $accessControl);
    }

    public function test_it_keys_route_based_entries_by_route_name(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { route: api_admin_dashboard, roles: ROLE_ADMIN }
            YAML);

        self::assertSame(['route: api_admin_dashboard' => ['ROLE_ADMIN']], $accessControl);
    }

    public function test_it_reads_bare_root_access_control(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(
            "access_control:\n    - path: ^/admin\n      roles: ROLE_ADMIN\n",
        );

        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $accessControl);
    }

    public function test_it_skips_entries_without_path_or_requirements(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { roles: ROLE_ADMIN }
                    - { path: ^/nothing }
            YAML);

        self::assertSame([], $accessControl);
    }

    public function test_it_skips_an_entry_with_a_blank_path_instead_of_recording_a_universal_match_pattern(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: '', roles: ROLE_ADMIN }
            YAML);

        self::assertSame([], $accessControl);
    }

    public function test_it_skips_an_entry_with_a_whitespace_only_path(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: '   ', roles: ROLE_ADMIN }
            YAML);

        self::assertSame([], $accessControl);
    }

    public function test_it_merges_access_control_across_root_and_when_env_sections(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/admin, roles: ROLE_ADMIN }
            when@prod:
                security:
                    access_control:
                        - { path: ^/metrics, roles: ROLE_MONITOR }
            YAML);

        self::assertSame(
            ['^/admin' => ['ROLE_ADMIN'], '^/metrics' => ['ROLE_MONITOR']],
            $accessControl,
        );
    }

    public function test_it_keeps_collecting_entries_after_one_without_a_path(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { roles: ROLE_ORPHAN }
                    - { path: ^/kept, roles: ROLE_KEPT }
            YAML);

        self::assertSame(['^/kept' => ['ROLE_KEPT']], $accessControl);
    }

    public function test_it_keeps_collecting_entries_after_one_without_requirements(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/bare }
                    - { path: ^/kept, roles: ROLE_KEPT }
            YAML);

        self::assertSame(['^/kept' => ['ROLE_KEPT']], $accessControl);
    }

    public function test_a_bare_root_partial_with_both_keys_yields_both_results(): void
    {
        $yaml = "access_control:\n    - { path: ^/admin, roles: ROLE_ADMIN }\nfirewalls:\n    main:\n        pattern: ^/\n";

        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $this->symfonyYamlSecurityConfigParser->parseAccessControl($yaml));
        self::assertSame(['^/'], $this->symfonyYamlSecurityConfigParser->parseFirewallRules($yaml));
    }

    public function test_a_bare_root_partial_with_only_firewalls_is_read(): void
    {
        $yaml = "firewalls:\n    api:\n        pattern: ^/api\n";

        self::assertSame(['^/api'], $this->symfonyYamlSecurityConfigParser->parseFirewallRules($yaml));
    }

    public function test_a_security_block_nested_under_an_unrelated_key_is_ignored(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            some_bundle:
                security:
                    access_control:
                        - { path: ^/phantom, roles: ROLE_PHANTOM }
            YAML);

        self::assertSame([], $accessControl);
    }

    public function test_it_logs_the_parse_error_when_yaml_is_unparseable(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('debug')
            ->with(
                'Skipping unparseable YAML during security-config mapping',
                self::callback(static fn (array $context): bool => \is_string($context['error'] ?? null) && '' !== $context['error']),
            );

        (new SymfonyYamlSecurityConfigParser($logger))->parseAccessControl("\t{ not: yaml");
    }

    public function test_it_trims_quoted_padded_paths_and_patterns(): void
    {
        self::assertSame(
            ['^/admin' => ['ROLE_ADMIN']],
            $this->symfonyYamlSecurityConfigParser->parseAccessControl(
                "security:\n    access_control:\n        - { path: ' ^/admin ', roles: ROLE_ADMIN }\n",
            ),
        );
        self::assertSame(
            ['^/api'],
            $this->symfonyYamlSecurityConfigParser->parseFirewallRules(
                "security:\n    firewalls:\n        api:\n            pattern: ' ^/api '\n",
            ),
        );
    }

    public function test_plural_roles_win_over_the_legacy_singular_role_key(): void
    {
        $accessControl = $this->symfonyYamlSecurityConfigParser->parseAccessControl(<<<'YAML'
            security:
                access_control:
                    - { path: ^/both, roles: ROLE_PLURAL, role: ROLE_SINGULAR }
            YAML);

        self::assertSame(['^/both' => ['ROLE_PLURAL']], $accessControl);
    }

    public function test_it_returns_empty_for_unparseable_yaml(): void
    {
        self::assertSame([], $this->symfonyYamlSecurityConfigParser->parseAccessControl("\t{ not: yaml"));
        self::assertSame([], $this->symfonyYamlSecurityConfigParser->parseFirewallRules("\t{ not: yaml"));
    }

    public function test_it_returns_empty_for_non_security_configuration(): void
    {
        $yaml = "framework:\n    secret: '%env(APP_SECRET)%'\n";

        self::assertSame([], $this->symfonyYamlSecurityConfigParser->parseAccessControl($yaml));
        self::assertSame([], $this->symfonyYamlSecurityConfigParser->parseFirewallRules($yaml));
    }

    public function test_it_lists_firewall_patterns(): void
    {
        $firewallRules = $this->symfonyYamlSecurityConfigParser->parseFirewallRules(<<<'YAML'
            security:
                firewalls:
                    main:
                        pattern: ^/
            YAML);

        self::assertSame(['^/'], $firewallRules);
    }

    public function test_it_flags_disabled_security_and_stateless_firewalls(): void
    {
        $firewallRules = $this->symfonyYamlSecurityConfigParser->parseFirewallRules(<<<'YAML'
            security:
                firewalls:
                    dev:
                        pattern: ^/(_(profiler|wdt)|css|images|js)/
                        security: false
                    api:
                        pattern: ^/api
                        stateless: true
            YAML);

        self::assertSame(
            ['^/(_(profiler|wdt)|css|images|js)/ (security: false)', '^/api (stateless)'],
            $firewallRules,
        );
    }

    public function test_it_falls_back_to_the_firewall_name_when_no_pattern_is_set(): void
    {
        $firewallRules = $this->symfonyYamlSecurityConfigParser->parseFirewallRules(<<<'YAML'
            security:
                firewalls:
                    main:
                        stateless: true
            YAML);

        self::assertSame(['main (stateless)'], $firewallRules);
    }
}
