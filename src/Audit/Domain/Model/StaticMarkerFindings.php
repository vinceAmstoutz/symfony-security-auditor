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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class StaticMarkerFindings
{
    private const array NOT_A_FINDING = ['scrubbed_secret', 'unmapped_access_control'];

    private const float DEFINITE_CONFIDENCE = 0.8;

    private const float LEAD_CONFIDENCE = 0.5;

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public static function from(RiskMarker $riskMarker, string $vulnerableCode): ?Vulnerability
    {
        if (\in_array($riskMarker->pattern(), self::NOT_A_FINDING, true)) {
            return null;
        }

        [$type, $severity] = self::classify($riskMarker->pattern());

        return Vulnerability::of(
            new VulnerabilityClassification($type, $severity, self::title($riskMarker), self::confidenceFor($severity)),
            new CodeLocation($riskMarker->filePath(), $riskMarker->line(), $riskMarker->line()),
            new VulnerabilityNarrative(
                \sprintf('Static analysis matched "%s" on this line: %s.', $riskMarker->pattern(), rtrim($riskMarker->description(), '.')),
                'Deterministic pattern match, reported without model analysis: trace how attacker-controlled input reaches this line.',
                \sprintf('Static pattern "%s" matched at %s:%d.', $riskMarker->pattern(), $riskMarker->filePath(), $riskMarker->line()),
                'Review the line, confirm whether untrusted input reaches it, and replace the construct with a safe equivalent when it does.',
            ),
            trim($vulnerableCode),
        );
    }

    private static function title(RiskMarker $riskMarker): string
    {
        return \sprintf('Static analysis: %s', str_replace('_', ' ', $riskMarker->pattern()));
    }

    private static function confidenceFor(VulnerabilitySeverity $vulnerabilitySeverity): float
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::LOW, VulnerabilitySeverity::INFO => self::LEAD_CONFIDENCE,
            default => self::DEFINITE_CONFIDENCE,
        };
    }

    /**
     * @return array{VulnerabilityType, VulnerabilitySeverity}
     */
    private static function classify(string $pattern): array
    {
        return match ($pattern) {
            'unserialize_call', 'unserialize_in_handler', 'php_serializer_transport' => [VulnerabilityType::INSECURE_DESERIALIZATION, VulnerabilitySeverity::HIGH],
            'eval_call', 'shell_invocation', 'process_construction', 'process_in_handler', 'extension_shell_or_file_sink' => [VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::HIGH],
            'native_query_concat' => [VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH],
            'doctrine_query', 'querybuilder_predicate', 'dynamic_order_by', 'querybuilder_no_setparameter' => [VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM],
            'ldap_unescaped_filter_concat', 'ldap_bind_variable_password' => [VulnerabilityType::LDAP_INJECTION, VulnerabilitySeverity::MEDIUM],
            'md5_or_sha1_security', 'rand_call' => [VulnerabilityType::WEAK_CRYPTOGRAPHY, VulnerabilitySeverity::MEDIUM],
            'weak_password_hasher_algorithm' => [VulnerabilityType::WEAK_PASSWORD_HASHING, VulnerabilitySeverity::HIGH],
            'hash_equals_missing', 'no_hash_equals' => [VulnerabilityType::MISSING_SIGNATURE_VERIFICATION, VulnerabilitySeverity::MEDIUM],
            'hardcoded_secret', 'env_credential_assignment', 'mercure_default_jwt_secret' => [VulnerabilityType::HARDCODED_SECRET, VulnerabilitySeverity::HIGH],
            'http_client_request' => [VulnerabilityType::SSRF, VulnerabilitySeverity::MEDIUM],
            'open_redirect', 'redirect_with_input' => [VulnerabilityType::OPEN_REDIRECT, VulnerabilitySeverity::MEDIUM],
            'mailer_header_setter' => [VulnerabilityType::MAILER_HEADER_INJECTION, VulnerabilitySeverity::MEDIUM],
            'file_sink', 'dynamic_file_inclusion', 'upload_handling' => [VulnerabilityType::PATH_TRAVERSAL, VulnerabilitySeverity::MEDIUM],
            'xml_external_entity' => [VulnerabilityType::XXE, VulnerabilitySeverity::MEDIUM],
            'twig_string_template', 'dynamic_include', 'expression_language_evaluate' => [VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM],
            'extension_is_safe_html', 'autoescape_false' => [VulnerabilityType::XSS, VulnerabilitySeverity::MEDIUM],
            'csrf_disabled' => [VulnerabilityType::MISSING_CSRF_PROTECTION, VulnerabilitySeverity::MEDIUM],
            'submit_request_all', 'allow_extra_fields', 'allow_extra_attributes', 'sensitive_setter', 'live_prop_writable' => [VulnerabilityType::MASS_ASSIGNMENT, VulnerabilitySeverity::MEDIUM],
            'serializer_groups_attribute', 'api_filter_declared', 'sonata_admin_sensitive_field_exposed', 'easyadmin_sensitive_field' => [VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP, VulnerabilitySeverity::LOW],
            'voter_default_true' => [VulnerabilityType::VOTER_BYPASS, VulnerabilitySeverity::MEDIUM],
            'role_check_only' => [VulnerabilityType::INSECURE_DIRECT_OBJECT_REFERENCE, VulnerabilitySeverity::LOW],
            'live_action_endpoint', 'sonata_admin_batch_action', 'easyadmin_destructive_action' => [VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::LOW],
            'firewall_security_false' => [VulnerabilityType::MISCONFIGURED_FIREWALL, VulnerabilitySeverity::MEDIUM],
            'self_validating_passport', 'supports_returns_null' => [VulnerabilityType::AUTHENTICATOR_BYPASS, VulnerabilitySeverity::MEDIUM],
            'cors_wildcard_with_credentials', 'unanchored_cors_origin_regex' => [VulnerabilityType::PERMISSIVE_CORS_ORIGIN, VulnerabilitySeverity::MEDIUM],
            'csp_unsafe_inline_or_eval' => [VulnerabilityType::WEAK_CONTENT_SECURITY_POLICY, VulnerabilitySeverity::MEDIUM],
            'hsts_disabled', 'cookie_secure_false', 'remember_me_secure_false' => [VulnerabilityType::MISSING_TRANSPORT_SECURITY, VulnerabilitySeverity::MEDIUM],
            'app_debug_enabled' => [VulnerabilityType::DEBUG_MODE_ENABLED, VulnerabilitySeverity::MEDIUM],
            'trusted_proxies_wildcard', 'forwarded_host_usage' => [VulnerabilityType::TRUSTED_PROXY_MISCONFIGURATION, VulnerabilitySeverity::MEDIUM],
            'mercure_permissive_topic_claim' => [VulnerabilityType::PERMISSIVE_MERCURE_TOPIC_SELECTOR, VulnerabilitySeverity::MEDIUM],
            'api_pagination_disabled', 'no_lock' => [VulnerabilityType::MISSING_RATE_LIMITING, VulnerabilitySeverity::LOW],
            'unserialize_session', 'superglobal_input', 'request_get', 'request_mapping_attribute', 'request_attributes_mutation' => [VulnerabilityType::UNSAFE_PARAMETER_BINDING, VulnerabilitySeverity::INFO],
            default => [VulnerabilityType::BUSINESS_LOGIC_FLAW, VulnerabilitySeverity::INFO],
        };
    }
}
