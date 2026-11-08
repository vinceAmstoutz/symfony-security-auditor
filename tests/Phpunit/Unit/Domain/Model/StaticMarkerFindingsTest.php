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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\StaticMarkerFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class StaticMarkerFindingsTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('mappedPatterns')]
    public function test_a_pattern_is_reported_under_its_mapped_type_and_severity(string $pattern, VulnerabilityType $type, VulnerabilitySeverity $severity): void
    {
        $finding = StaticMarkerFindings::from(RiskMarker::create('src/A.php', 4, $pattern, 'Some description.'), 'code();');

        self::assertNotNull($finding);
        self::assertSame($type, $finding->type());
        self::assertSame($severity, $finding->severity());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_unmapped_pattern_is_reported_as_an_info_lead(): void
    {
        $finding = StaticMarkerFindings::from(RiskMarker::create('src/A.php', 4, 'sarif:psalm:TaintedHtml', 'Tainted.'), 'code();');

        self::assertNotNull($finding);
        self::assertSame(VulnerabilityType::BUSINESS_LOGIC_FLAW, $finding->type());
        self::assertSame(VulnerabilitySeverity::INFO, $finding->severity());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('markersThatAreNotFindings')]
    public function test_a_marker_that_is_not_a_vulnerability_is_not_reported(string $pattern): void
    {
        self::assertNull(StaticMarkerFindings::from(RiskMarker::create('src/A.php', 4, $pattern, 'Description.'), 'code();'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_finding_names_the_match_and_its_location(): void
    {
        $finding = StaticMarkerFindings::from(RiskMarker::create('src/Legacy.php', 12, 'unserialize_call', 'unserialize() on a payload.'), '   unserialize($payload);  ');

        self::assertNotNull($finding);
        self::assertSame('src/Legacy.php', $finding->filePath());
        self::assertSame(12, $finding->lineStart());
        self::assertSame(12, $finding->lineEnd());
        self::assertSame('unserialize($payload);', $finding->vulnerableCode());
        self::assertSame('Static analysis: unserialize call', $finding->title());
        self::assertSame('Static analysis matched "unserialize_call" on this line: unserialize() on a payload.', $finding->description());
        self::assertSame('Static pattern "unserialize_call" matched at src/Legacy.php:12.', $finding->proof());
        self::assertFalse($finding->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('confidenceBySeverity')]
    public function test_the_confidence_follows_how_definite_the_severity_is(string $pattern, float $confidence): void
    {
        $finding = StaticMarkerFindings::from(RiskMarker::create('src/A.php', 1, $pattern, 'Description.'), 'code();');

        self::assertNotNull($finding);
        self::assertSame($confidence, $finding->confidence());
    }

    /**
     * @return iterable<string, array{string, VulnerabilityType, VulnerabilitySeverity}>
     */
    public static function mappedPatterns(): iterable
    {
        yield 'unserialize_call' => ['unserialize_call', VulnerabilityType::INSECURE_DESERIALIZATION, VulnerabilitySeverity::HIGH];
        yield 'unserialize_in_handler' => ['unserialize_in_handler', VulnerabilityType::INSECURE_DESERIALIZATION, VulnerabilitySeverity::HIGH];
        yield 'php_serializer_transport' => ['php_serializer_transport', VulnerabilityType::INSECURE_DESERIALIZATION, VulnerabilitySeverity::HIGH];
        yield 'eval_call' => ['eval_call', VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::HIGH];
        yield 'shell_invocation' => ['shell_invocation', VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::HIGH];
        yield 'process_construction' => ['process_construction', VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::HIGH];
        yield 'process_in_handler' => ['process_in_handler', VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::HIGH];
        yield 'extension_shell_or_file_sink' => ['extension_shell_or_file_sink', VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::HIGH];
        yield 'native_query_concat' => ['native_query_concat', VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH];
        yield 'doctrine_query' => ['doctrine_query', VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'querybuilder_predicate' => ['querybuilder_predicate', VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'dynamic_order_by' => ['dynamic_order_by', VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'querybuilder_no_setparameter' => ['querybuilder_no_setparameter', VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'ldap_unescaped_filter_concat' => ['ldap_unescaped_filter_concat', VulnerabilityType::LDAP_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'ldap_bind_variable_password' => ['ldap_bind_variable_password', VulnerabilityType::LDAP_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'weak_password_hasher_algorithm' => ['weak_password_hasher_algorithm', VulnerabilityType::WEAK_PASSWORD_HASHING, VulnerabilitySeverity::HIGH];
        yield 'hash_equals_missing' => ['hash_equals_missing', VulnerabilityType::MISSING_SIGNATURE_VERIFICATION, VulnerabilitySeverity::MEDIUM];
        yield 'no_hash_equals' => ['no_hash_equals', VulnerabilityType::MISSING_SIGNATURE_VERIFICATION, VulnerabilitySeverity::MEDIUM];
        yield 'hardcoded_secret' => ['hardcoded_secret', VulnerabilityType::HARDCODED_SECRET, VulnerabilitySeverity::HIGH];
        yield 'env_credential_assignment' => ['env_credential_assignment', VulnerabilityType::HARDCODED_SECRET, VulnerabilitySeverity::HIGH];
        yield 'mercure_default_jwt_secret' => ['mercure_default_jwt_secret', VulnerabilityType::HARDCODED_SECRET, VulnerabilitySeverity::HIGH];
        yield 'http_client_request' => ['http_client_request', VulnerabilityType::SSRF, VulnerabilitySeverity::MEDIUM];
        yield 'open_redirect' => ['open_redirect', VulnerabilityType::OPEN_REDIRECT, VulnerabilitySeverity::MEDIUM];
        yield 'redirect_with_input' => ['redirect_with_input', VulnerabilityType::OPEN_REDIRECT, VulnerabilitySeverity::MEDIUM];
        yield 'mailer_header_setter' => ['mailer_header_setter', VulnerabilityType::MAILER_HEADER_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'file_sink' => ['file_sink', VulnerabilityType::PATH_TRAVERSAL, VulnerabilitySeverity::MEDIUM];
        yield 'dynamic_file_inclusion' => ['dynamic_file_inclusion', VulnerabilityType::PATH_TRAVERSAL, VulnerabilitySeverity::MEDIUM];
        yield 'upload_handling' => ['upload_handling', VulnerabilityType::PATH_TRAVERSAL, VulnerabilitySeverity::MEDIUM];
        yield 'xml_external_entity' => ['xml_external_entity', VulnerabilityType::XXE, VulnerabilitySeverity::MEDIUM];
        yield 'twig_string_template' => ['twig_string_template', VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'dynamic_include' => ['dynamic_include', VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'expression_language_evaluate' => ['expression_language_evaluate', VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM];
        yield 'extension_is_safe_html' => ['extension_is_safe_html', VulnerabilityType::XSS, VulnerabilitySeverity::MEDIUM];
        yield 'autoescape_false' => ['autoescape_false', VulnerabilityType::XSS, VulnerabilitySeverity::MEDIUM];
        yield 'csrf_disabled' => ['csrf_disabled', VulnerabilityType::MISSING_CSRF_PROTECTION, VulnerabilitySeverity::MEDIUM];
        yield 'submit_request_all' => ['submit_request_all', VulnerabilityType::MASS_ASSIGNMENT, VulnerabilitySeverity::MEDIUM];
        yield 'allow_extra_fields' => ['allow_extra_fields', VulnerabilityType::MASS_ASSIGNMENT, VulnerabilitySeverity::MEDIUM];
        yield 'allow_extra_attributes' => ['allow_extra_attributes', VulnerabilityType::MASS_ASSIGNMENT, VulnerabilitySeverity::MEDIUM];
        yield 'sensitive_setter' => ['sensitive_setter', VulnerabilityType::MASS_ASSIGNMENT, VulnerabilitySeverity::MEDIUM];
        yield 'live_prop_writable' => ['live_prop_writable', VulnerabilityType::MASS_ASSIGNMENT, VulnerabilitySeverity::MEDIUM];
        yield 'serializer_groups_attribute' => ['serializer_groups_attribute', VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP, VulnerabilitySeverity::LOW];
        yield 'api_filter_declared' => ['api_filter_declared', VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP, VulnerabilitySeverity::LOW];
        yield 'sonata_admin_sensitive_field_exposed' => ['sonata_admin_sensitive_field_exposed', VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP, VulnerabilitySeverity::LOW];
        yield 'easyadmin_sensitive_field' => ['easyadmin_sensitive_field', VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP, VulnerabilitySeverity::LOW];
        yield 'voter_default_true' => ['voter_default_true', VulnerabilityType::VOTER_BYPASS, VulnerabilitySeverity::MEDIUM];
        yield 'role_check_only' => ['role_check_only', VulnerabilityType::INSECURE_DIRECT_OBJECT_REFERENCE, VulnerabilitySeverity::LOW];
        yield 'live_action_endpoint' => ['live_action_endpoint', VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::LOW];
        yield 'sonata_admin_batch_action' => ['sonata_admin_batch_action', VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::LOW];
        yield 'easyadmin_destructive_action' => ['easyadmin_destructive_action', VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::LOW];
        yield 'firewall_security_false' => ['firewall_security_false', VulnerabilityType::MISCONFIGURED_FIREWALL, VulnerabilitySeverity::MEDIUM];
        yield 'self_validating_passport' => ['self_validating_passport', VulnerabilityType::AUTHENTICATOR_BYPASS, VulnerabilitySeverity::MEDIUM];
        yield 'supports_returns_null' => ['supports_returns_null', VulnerabilityType::AUTHENTICATOR_BYPASS, VulnerabilitySeverity::MEDIUM];
        yield 'cors_wildcard_with_credentials' => ['cors_wildcard_with_credentials', VulnerabilityType::PERMISSIVE_CORS_ORIGIN, VulnerabilitySeverity::MEDIUM];
        yield 'unanchored_cors_origin_regex' => ['unanchored_cors_origin_regex', VulnerabilityType::PERMISSIVE_CORS_ORIGIN, VulnerabilitySeverity::MEDIUM];
        yield 'csp_unsafe_inline_or_eval' => ['csp_unsafe_inline_or_eval', VulnerabilityType::WEAK_CONTENT_SECURITY_POLICY, VulnerabilitySeverity::MEDIUM];
        yield 'hsts_disabled' => ['hsts_disabled', VulnerabilityType::MISSING_TRANSPORT_SECURITY, VulnerabilitySeverity::MEDIUM];
        yield 'cookie_secure_false' => ['cookie_secure_false', VulnerabilityType::MISSING_TRANSPORT_SECURITY, VulnerabilitySeverity::MEDIUM];
        yield 'remember_me_secure_false' => ['remember_me_secure_false', VulnerabilityType::MISSING_TRANSPORT_SECURITY, VulnerabilitySeverity::MEDIUM];
        yield 'app_debug_enabled' => ['app_debug_enabled', VulnerabilityType::DEBUG_MODE_ENABLED, VulnerabilitySeverity::MEDIUM];
        yield 'trusted_proxies_wildcard' => ['trusted_proxies_wildcard', VulnerabilityType::TRUSTED_PROXY_MISCONFIGURATION, VulnerabilitySeverity::MEDIUM];
        yield 'forwarded_host_usage' => ['forwarded_host_usage', VulnerabilityType::TRUSTED_PROXY_MISCONFIGURATION, VulnerabilitySeverity::MEDIUM];
        yield 'mercure_permissive_topic_claim' => ['mercure_permissive_topic_claim', VulnerabilityType::PERMISSIVE_MERCURE_TOPIC_SELECTOR, VulnerabilitySeverity::MEDIUM];
        yield 'api_pagination_disabled' => ['api_pagination_disabled', VulnerabilityType::MISSING_RATE_LIMITING, VulnerabilitySeverity::LOW];
        yield 'no_lock' => ['no_lock', VulnerabilityType::MISSING_RATE_LIMITING, VulnerabilitySeverity::LOW];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function markersThatAreNotFindings(): iterable
    {
        yield 'scrubbed secret' => ['scrubbed_secret'];
        yield 'unmapped access control' => ['unmapped_access_control'];
        yield 'superglobal input' => ['superglobal_input'];
        yield 'request get' => ['request_get'];
        yield 'request mapping attribute' => ['request_mapping_attribute'];
        yield 'unserialize session' => ['unserialize_session'];
        yield 'request attributes mutation' => ['request_attributes_mutation'];
    }

    /**
     * @return iterable<string, array{string, float}>
     */
    public static function confidenceBySeverity(): iterable
    {
        yield 'high' => ['unserialize_call', 0.8];
        yield 'medium' => ['md5_or_sha1_security', 0.8];
        yield 'low' => ['role_check_only', 0.5];
        yield 'info' => ['sarif:psalm:TaintedHtml', 0.5];
    }
}
