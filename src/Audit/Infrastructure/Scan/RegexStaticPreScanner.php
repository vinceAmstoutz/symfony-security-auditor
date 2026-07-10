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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Pattern dictionary is split by file-type bucket. Each entry maps a regex
 * to a short pattern label and a human-readable description. The scanner
 * walks every file once, matches per-line, and emits one marker per match.
 */
final readonly class RegexStaticPreScanner implements StaticPreScannerInterface
{
    /**
     * Bump when the built-in PATTERNS dictionary changes in a way that would
     * alter scan output for existing chunk content. Folded into the attacker
     * cache key so stale entries are invalidated.
     */
    public const int CACHE_VERSION = 13;

    /**
     * @param array<string, array<string, array{regex: string, description: string}>> $customPatterns extra patterns merged into the static dictionary keyed by file-type bucket
     */
    public function __construct(
        private array $customPatterns = [],
    ) {}

    /**
     * @var array<string, array<string, array{regex: string, description: string}>>
     */
    private const array PATTERNS = [
        ProjectFileType::PHP->value => [
            'unserialize_call' => [
                'regex' => '/\b(?:unserialize|igbinary_unserialize)\s*\(/',
                'description' => 'unserialize() on potentially untrusted payload — RCE gadget chain risk',
            ],
            'shell_invocation' => [
                'regex' => '/\b(?:shell_exec|exec|passthru|proc_open|system|popen)\s*\(/',
                'description' => 'Shell invocation — verify no user-input concatenation',
            ],
            'md5_or_sha1_security' => [
                'regex' => '/\b(?:md5|sha1)\s*\(/',
                'description' => 'md5/sha1 — confirm not used for passwords or signatures',
            ],
            'rand_call' => [
                'regex' => '/\b(?:rand|mt_rand)\s*\(/',
                'description' => 'rand/mt_rand — insecure for tokens; use random_int',
            ],
            'eval_call' => [
                'regex' => '/\beval\s*\(/',
                'description' => 'eval() on dynamic input — RCE risk',
            ],
            'http_client_request' => [
                'regex' => '/\bHttpClient(?:Interface)?\b[^;]{0,400}->request\s*\(/s',
                'description' => 'HttpClient request — verify host allowlist (SSRF)',
            ],
            'mailer_header_setter' => [
                'regex' => '/->(?:from|subject|addBcc|bcc|addCc|cc|to|replyTo)\s*\(/',
                'description' => 'Mailer header setter — verify no user-input concatenation (header injection)',
            ],
            'hash_equals_missing' => [
                'regex' => '/\$\w*(?:Signature|Hash|Hmac|Token)\s*[!=]==|[!=]==\s*\$\w*(?:Signature|Hash|Hmac|Token)/i',
                'description' => 'Non-constant-time signature compare — use hash_equals()',
            ],
            'unserialize_session' => [
                'regex' => '/->getSession\(\)->get\([^)]*\)/',
                'description' => 'Session value read — verify no unserialize on session payload',
            ],
            'expression_language_evaluate' => [
                'regex' => '/->evaluate\s*\(/',
                'description' => 'ExpressionLanguage::evaluate() — verify expression not built from user input',
            ],
        ],
        ProjectFileType::CONTROLLER->value => [
            'request_get' => [
                'regex' => '/\$request->(?:get|getContent|query->get|request->get|attributes->get)\s*\(/',
                'description' => 'Request input read — trace flow to dangerous sinks',
            ],
            'redirect_with_input' => [
                'regex' => '/->redirect\s*\(.{0,200}\$/s',
                'description' => 'Redirect with variable target — verify protocol/host allowlist (open redirect)',
            ],
            'submit_request_all' => [
                'regex' => '/->submit\s*\(\s*\$request->\w+->all\s*\(\s*\)\s*\)/s',
                'description' => 'Form submit($request->...->all()) — mass-assignment risk',
            ],
            'map_request_payload' => [
                'regex' => '/#\[MapRequestPayload(?:\s*\()/',
                'description' => '#[MapRequestPayload] — verify the DTO has validation constraints and no privileged setters',
            ],
        ],
        ProjectFileType::VOTER->value => [
            'voter_default_true' => [
                'regex' => '/return\s+true\s*;/',
                'description' => 'Voter returning true — verify it is not an unrestricted default branch',
            ],
            'role_check_only' => [
                'regex' => '/->getRoles\s*\(\s*\)/',
                'description' => 'getRoles() consulted — verify per-resource ownership check is also performed',
            ],
        ],
        ProjectFileType::REPOSITORY->value => [
            'native_query_concat' => [
                'regex' => '/->executeQuery\s*\(\s*[\'"][^\'"]*\.\s*\$/',
                'description' => 'Native SQL with string concatenation — SQL injection risk',
            ],
            'dynamic_order_by' => [
                'regex' => '/->orderBy\s*\(\s*\$/s',
                'description' => 'Dynamic orderBy — Doctrine does NOT parameterize ORDER BY',
            ],
            'querybuilder_no_setparameter' => [
                'regex' => '/->where\s*\(\s*[\'"][^\'"]*\$/',
                'description' => 'where() with string interpolation — verify setParameter is used',
            ],
        ],
        ProjectFileType::FORM->value => [
            'csrf_disabled' => [
                'regex' => '/[\'"]csrf_protection[\'"]\s*=>\s*false/',
                'description' => 'CSRF protection disabled — state-changing forms must enable it',
            ],
            'allow_extra_fields' => [
                'regex' => '/[\'"]allow_extra_fields[\'"]\s*=>\s*true/',
                'description' => 'allow_extra_fields: true — mass-assignment vector',
            ],
        ],
        ProjectFileType::API_RESOURCE->value => [
            'api_pagination_disabled' => [
                'regex' => '/paginationEnabled\s*[:=]\s*false|paginationClientEnabled\s*[:=]\s*true/',
                'description' => 'API Platform pagination disabled or client-controlled — unbounded collection responses',
            ],
            'api_filter_declared' => [
                'regex' => '/#\[\s*ApiFilter\s*\(/',
                'description' => 'ApiFilter declared — verify filtered properties are not sensitive or foreign-owned (data-exfiltration oracle)',
            ],
            'serializer_groups_attribute' => [
                'regex' => '/#\[\s*Groups\s*\(|@Groups\s*\(/',
                'description' => 'Serializer #[Groups] attribute — verify write groups do not expose privileged fields (roles, isAdmin, passwordHash) to mass assignment',
            ],
        ],
        ProjectFileType::LIVE_COMPONENT->value => [
            'live_prop_writable' => [
                'regex' => '/#\[\s*LiveProp\s*\([^)]*writable\s*:\s*true/',
                'description' => 'Writable LiveProp — client-controlled before any action runs; verify it is not a privileged or owned-resource field',
            ],
            'live_action_endpoint' => [
                'regex' => '/#\[\s*LiveAction\b/',
                'description' => 'LiveAction — a routeless HTTP endpoint; verify an #[IsGranted]/denyAccessUnlessGranted guard covers it',
            ],
        ],
        ProjectFileType::ENTITY->value => [
            'sensitive_setter' => [
                'regex' => '/public\s+function\s+set(?:Roles?|IsAdmin|IsSuperAdmin|PasswordHash|Password|Admin|SuperAdmin|Superuser)\b/i',
                'description' => 'Public setter on sensitive field — verify it is not bound by a form',
            ],
            'serializer_groups_attribute' => [
                'regex' => '/#\[\s*Groups\s*\(|@Groups\s*\(/',
                'description' => 'Serializer #[Groups] attribute — verify write groups do not expose privileged fields (roles, isAdmin, passwordHash) to mass assignment',
            ],
        ],
        ProjectFileType::TWIG_EXTENSION->value => [
            'extension_shell_or_file_sink' => [
                'regex' => '/\b(?:shell_exec|exec|passthru|proc_open|system|popen|file_get_contents|file_put_contents)\s*\(|\b(?:include|include_once|require|require_once)\b/',
                'description' => 'Shell/file sink inside a Twig extension — reachable from any template calling this function/filter; verify no template-supplied argument reaches it (RCE/LFI)',
            ],
            'extension_is_safe_html' => [
                'regex' => '/[\'"]is_safe[\'"]\s*=>\s*\[\s*[\'"]html[\'"]\s*\]/',
                'description' => 'is_safe => [\'html\'] declared — verify the returned string is built only from hardcoded markup or sanitized input, not raw user/DB content (stored XSS otherwise)',
            ],
        ],
        ProjectFileType::TEMPLATE->value => [
            'raw_filter' => [
                'regex' => '/\|\s*raw\b/',
                'description' => '|raw filter — verify upstream sanitization',
            ],
            'autoescape_false' => [
                'regex' => '/autoescape\s+false/',
                'description' => 'autoescape false — XSS risk',
            ],
            'dynamic_include' => [
                'regex' => '/\{\%\s*include\s+[a-zA-Z_]+\s*\%\}|\{\{\s*include\s*\(/',
                'description' => 'Dynamic template include — SSTI risk',
            ],
        ],
        ProjectFileType::CONFIG->value => [
            'hardcoded_secret' => [
                'regex' => '/(?:password|secret|api[_-]?key|token)\s*:\s*[\'"]?(?!%env\()[A-Za-z0-9+\/=]{16,}/i',
                'description' => 'Possible hardcoded credential — use %env(...)% reference',
            ],
            'cookie_secure_false' => [
                'regex' => '/cookie_secure\s*:\s*false/',
                'description' => 'cookie_secure: false — session cookie sent over plain HTTP',
            ],
            'cors_wildcard_with_credentials' => [
                'regex' => '/allow_origin[^:]*:\s*[\'"]?\*/',
                'description' => 'CORS allow_origin: * — verify allow_credentials is not also true',
            ],
            'firewall_security_false' => [
                'regex' => '/security\s*:\s*false/',
                'description' => 'firewall security: false — verify the route is intentionally anonymous',
            ],
            'php_serializer_transport' => [
                'regex' => '/serializer\s*:\s*[\'"]?php_serialize/',
                'description' => 'Messenger transport with php_serialize — PHP-native unserialize on dequeue',
            ],
            'env_credential_assignment' => [
                'regex' => '/^\s*[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*\S+/',
                'description' => 'Credential assigned in a committed dotenv file — move it to secrets storage (vault) or an untracked .env.local',
            ],
            'scrubbed_secret' => [
                'regex' => '/\*\*\*REDACTED:/',
                'description' => 'A credential-shaped value was redacted here before analysis — a real secret is committed in this file',
            ],
        ],
        ProjectFileType::AUTHENTICATOR->value => [
            'self_validating_passport' => [
                'regex' => '/new\s+SelfValidatingPassport\s*\(/',
                'description' => 'SelfValidatingPassport — skips credential check; verify the flow is OAuth/token, not password',
            ],
            'supports_returns_null' => [
                'regex' => '/public\s+function\s+supports\s*\([^)]*\)\s*:\s*\??bool\s*\{[\s\S]{0,500}?return\s+null\s*;/s',
                'description' => 'supports() returning null — Symfony treats null as "supports", silently letting non-matching paths through',
            ],
        ],
        ProjectFileType::MESSENGER_HANDLER->value => [
            'unserialize_in_handler' => [
                'regex' => '/\b(?:unserialize|igbinary_unserialize)\s*\(/',
                'description' => 'unserialize() in handler — gadget-chain risk on transported payload',
            ],
            'process_in_handler' => [
                'regex' => '/new\s+Process\s*\(/',
                'description' => 'Process construction in handler — verify argv is not built from message fields',
            ],
        ],
        ProjectFileType::WEBHOOK_CONSUMER->value => [
            'no_hash_equals' => [
                'regex' => '/(?:signature|hmac|hash)[^;]{0,80}[!=]==/is',
                'description' => 'Signature/HMAC compared with === — use hash_equals() for constant-time',
            ],
        ],
        ProjectFileType::EVENT_SUBSCRIBER->value => [
            'request_attributes_mutation' => [
                'regex' => '/->getRequest\(\)->attributes->set\s*\(/',
                'description' => 'Subscriber mutating request attributes — verify it cannot inject privileged values',
            ],
        ],
        ProjectFileType::NORMALIZER->value => [
            'allow_extra_attributes' => [
                'regex' => '/[\'"]allow_extra_attributes[\'"]\s*=>\s*true/',
                'description' => 'Denormalizer with allow_extra_attributes: true — mass-assignment vector',
            ],
        ],
        ProjectFileType::SCHEDULER->value => [
            'no_lock' => [
                'regex' => '/RecurringMessage::every|#\[AsSchedule/',
                'description' => 'Scheduled task — verify lock is held to prevent overlapping runs',
            ],
        ],
    ];

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<RiskMarker>
     *
     * @throws InvalidRiskMarkerException
     */
    #[Override]
    public function scan(array $files): array
    {
        $markers = [];

        foreach ($files as $file) {
            $bucket = $file->type();
            $patternsForBucket = [
                ...$this->genericPhpPatternsFor($file),
                ...(self::PATTERNS[$bucket] ?? []),
                ...($this->customPatterns[$bucket] ?? []),
            ];

            foreach ($patternsForBucket as $label => $entry) {
                $matches = $this->matchLines($file->content(), $entry['regex']);

                foreach ($matches as $match) {
                    $markers[] = RiskMarker::create(
                        $file->relativePath(),
                        $match,
                        $label,
                        $entry['description'],
                    );
                }
            }
        }

        return $markers;
    }

    /**
     * The `php` bucket's generic sink patterns (unserialize, eval, shell exec,
     * weak crypto, insecure RNG, SSRF-prone HttpClient calls, mailer header
     * setters, non-constant-time compares, ExpressionLanguage evaluation) are
     * dangerous in any PHP source file, not only plain services: a controller
     * or messenger handler calling `unserialize()` on request input is at least
     * as exploitable. `scan()` selects a single type bucket per file, so
     * without this every non-`php` component (controller, voter, entity,
     * repository, form, authenticator, …) would miss those markers — and under
     * the `fast` profile's lean-mode filter, which drops files carrying zero
     * markers, such a file would be excluded from the audit entirely. Keyed by
     * label, so a `php`-typed file (whose own bucket already is the `php` set)
     * gets each pattern exactly once after the spread merge. Non-PHP files
     * (Twig templates, YAML config) are excluded — these patterns are
     * PHP-source specific.
     *
     * @return array<string, array{regex: string, description: string}>
     */
    private function genericPhpPatternsFor(ProjectFile $projectFile): array
    {
        if ('php' !== pathinfo($projectFile->relativePath(), \PATHINFO_EXTENSION)) {
            return [];
        }

        return self::PATTERNS[ProjectFileType::PHP->value];
    }

    /**
     * @return list<int>
     */
    private function matchLines(string $content, string $regex): array
    {
        if ($this->hasDotAllModifier($regex)) {
            return $this->matchAcrossLines($content, $regex);
        }

        $lines = explode("\n", $content);
        $matches = [];

        foreach ($lines as $index => $line) {
            if (1 === preg_match($regex, $line)) {
                $matches[] = $index + 1;
            }
        }

        return $matches;
    }

    /**
     * A well-formed PCRE pattern always has a non-empty delimiter and its
     * closing counterpart somewhere in the string — both are asserted rather
     * than branched on, since a pattern violating either is already
     * malformed and will fail its own `preg_match()` call regardless of what
     * this method returns.
     */
    private function hasDotAllModifier(string $regex): bool
    {
        \assert('' !== $regex, 'A configured regex pattern must not be empty');

        $closingDelimiter = match ($regex[0]) {
            '(' => ')',
            '{' => '}',
            '[' => ']',
            '<' => '>',
            default => $regex[0],
        };

        $closingPosition = strrpos($regex, $closingDelimiter, 1);
        \assert(false !== $closingPosition, 'A well-formed PCRE pattern contains its closing delimiter');

        return str_contains(substr($regex, $closingPosition + 1), 's');
    }

    /**
     * A cross-line match's own security-relevant token (`return null;`, the
     * actual `->request(` call) sits at the END of the match, not its start —
     * a marker line pointing to the match's opening keyword (e.g. `public
     * function supports(`) is often a structural line the code slicer already
     * retains unconditionally, restoring nothing.
     *
     * @return list<int>
     */
    private function matchAcrossLines(string $content, string $regex): array
    {
        preg_match_all($regex, $content, $matches, \PREG_OFFSET_CAPTURE);

        $lines = [];
        foreach ($matches[0] as [$matchedText, $startOffset]) {
            $lines[] = substr_count($content, "\n", 0, $startOffset + \strlen($matchedText)) + 1;
        }

        return array_values(array_unique($lines));
    }
}
