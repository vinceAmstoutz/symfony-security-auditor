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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AttackerPromptBuilder implements AttackerPromptBuilderInterface
{
    /**
     * Wire-format version of the prompt this builder emits. Folded into the
     * attacker cache key so that a wording change automatically invalidates
     * previously-cached LLM responses. Bump whenever the prompt structure or
     * skill blocks change in a way the LLM is expected to react to.
     */
    public const int PROMPT_VERSION = 9;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    public const bool DEFAULT_EMIT_ALL_SKILLS = false;

    public function __construct(
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        private bool $emitAllSkills = self::DEFAULT_EMIT_ALL_SKILLS,
    ) {}

    /**
     * Skill-block emission order — by attack-surface priority, NOT alphabetical.
     * The LLM weights earlier-in-context instructions more heavily (primacy), so
     * higher-risk surfaces are listed first.
     *
     * @var list<ProjectFileType>
     */
    private const array SKILL_PRIORITY = [
        ProjectFileType::CONTROLLER,
        ProjectFileType::AUTHENTICATOR,
        ProjectFileType::VOTER,
        ProjectFileType::WEBHOOK_CONSUMER,
        ProjectFileType::MESSENGER_HANDLER,
        ProjectFileType::EVENT_SUBSCRIBER,
        ProjectFileType::NORMALIZER,
        ProjectFileType::SCHEDULER,
        ProjectFileType::FORM,
        ProjectFileType::REPOSITORY,
        ProjectFileType::ENTITY,
        ProjectFileType::TEMPLATE,
        ProjectFileType::CONFIG,
        ProjectFileType::PHP,
    ];

    /**
     * Expert skill blocks injected into the system prompt when files of the matching
     * ProjectFile::type() appear in the chunk. Each block lists both attack patterns
     * to hunt AND patterns explicitly NOT to flag, reducing false positives.
     *
     * @var array<string, string>
     */
    private const array SKILLS = [
        ProjectFileType::CONTROLLER->value => <<<'SKILL'
            <skills role="controller">
            Hunt:
            - Missing `denyAccessUnlessGranted()` / `#[IsGranted]` on state-changing or sensitive read actions.
            - `ParamConverter` / `MapEntity` / `#[MapRequestPayload]` / `#[MapQueryString]` flows for IDOR: path id → entity fetch with no ownership check.
            - Mass-assignment: form `->submit($request->request->all())` without `allow_extra_fields: false` or restricted setters.
            - `#[MapRequestPayload]` / `#[MapQueryString]` DTO mapping over an entity-shaped class with public mutable properties (mass-assignment via Serializer).
            - Redirect targets and `RedirectResponse` arguments against open-redirect via user-controlled URLs.
            - File-upload handlers: missing MIME validation, predictable upload paths, no content-type enforcement.
            - Authentication endpoints (login, password reset, 2FA, registration) without rate-limiter binding (`#[IsSignatureValid]` / `RateLimiterFactory::create()` / `framework.rate_limiter`).
            - `Request::get()` / `getContent()` flowing into Doctrine raw queries, `exec`, `passthru`, `eval`, `unserialize`, `simplexml_load_string`.
            - Live Components: `#[LiveAction]` / `#[LiveProp(writable: true)]` exposing privileged setters or unbounded properties to the browser.
            Do NOT flag:
            - Controllers inheriting `denyAccessUnlessGranted()` from a parent class or a `#[IsGranted]` attribute on the class itself.
            - Routes restricted by `methods: ['POST']` plus a CSRF-protected form — the form covers the CSRF concern.
            - `#[MapRequestPayload]` / `#[MapQueryString]` over a DTO with validation constraints (`#[Assert\…]`) AND no privileged setters.
            </skills>
            SKILL,
        ProjectFileType::AUTHENTICATOR->value => <<<'SKILL'
            <skills role="authenticator">
            Hunt:
            - `authenticate()` returning a `SelfValidatingPassport` for password-bearing flows (skips credential check → auth bypass).
            - `supports()` returning `null` instead of `false` for unsupported requests — `null` means "supports", silently letting non-matching paths through.
            - `onAuthenticationSuccess()` calling `RedirectResponse` with a user-controlled `_target_path` / `referer` without protocol+host allowlist.
            - `AccessTokenHandler::getUserBadgeFrom($accessToken)` not verifying signature/audience/issuer of JWT/opaque tokens.
            - Custom `LoginFormAuthenticator` storing the password in the session, log, or exception trace.
            - Missing `CsrfTokenBadge` on form-based login authenticators where CSRF was previously enforced.
            - OAuth/OIDC handlers omitting `state` parameter verification (CSRF on auth callback) or PKCE for public clients.
            - `UserBadge::setUserLoader()` query running with a user-controlled `identifier` without normalization (`User WHERE email = :id` accepting wildcards/case-insensitive variants).
            Do NOT flag:
            - Authenticators that explicitly throw `AuthenticationException` on missing credentials.
            - `RememberMeBadge` on long-lived auth — that is the documented opt-in pattern.
            </skills>
            SKILL,
        ProjectFileType::WEBHOOK_CONSUMER->value => <<<'SKILL'
            <skills role="webhook_consumer">
            Hunt:
            - `RequestParserInterface::parse()` / `RemoteEventConsumerInterface::consume()` consuming the payload without HMAC / signature verification (`hash_equals` with the configured secret).
            - Signature compared with `===` / `==` (timing-attack vulnerable) instead of `hash_equals()`.
            - Missing replay-attack defense: no nonce check, no timestamp check, no idempotency key — same payload can be replayed indefinitely.
            - `#[AsRemoteEventConsumer]` handler trusting `$payload['user_id']` / `$payload['amount']` without re-validating against the authenticated source.
            - JSON / XML parsers without bounded depth/size (DoS via large or deeply-nested payloads).
            - Webhook routes mounted under a firewall that allows anonymous access AND lacks IP allowlist or mutual-TLS gating.
            Do NOT flag:
            - Webhook handlers calling `hash_equals($expected, $received)` against the framework's secret.
            - `WebhookComponent::validate($request, $secret)` invocations — those use constant-time comparison internally.
            </skills>
            SKILL,
        ProjectFileType::MESSENGER_HANDLER->value => <<<'SKILL'
            <skills role="messenger_handler">
            Hunt:
            - `#[AsMessageHandler]` / `MessageHandlerInterface::__invoke()` calling `unserialize()` / `igbinary_unserialize()` on payload fields.
            - Handlers invoking `Process` / `shell_exec` / SQL with values from `$message` without sanitization (queue-to-shell injection).
            - Missing idempotency: handler with side effects (charge card, send email, mutate balance) not deduping by message id (`AmqpStamp::getApplicationHeaders()['x-message-id']`).
            - No replay protection: handler trusts `$message->createdAt` / `$message->userId` without verifying current state (stale message attack).
            - Transport configured with `serializer: php` (PHP-native serialize on untrusted bus) — gadget-chain RCE.
            - Handler swallowing exceptions silently → poisoned messages re-driven infinitely.
            - Privileged action triggered solely by message presence with no authorization (`InvalidateUserCommand`, `PromoteToAdmin`, etc.).
            Do NOT flag:
            - Handlers using the default `JsonSerializer` transport — well-typed via Symfony Serializer.
            - Handlers using `Symfony\Component\Messenger\Stamp\BusNameStamp` / `TransportNamesStamp` — those are routing, not security smells.
            </skills>
            SKILL,
        ProjectFileType::EVENT_SUBSCRIBER->value => <<<'SKILL'
            <skills role="event_subscriber">
            Hunt:
            - `KernelEvents::CONTROLLER` / `KernelEvents::REQUEST` subscribers mutating `$event->getRequest()->attributes` to inject privileged values (role, user id) before the controller runs.
            - `SecurityEvents::AUTHENTICATION_SUCCESS` listeners auto-elevating roles based on payload fields without re-checking the source.
            - `kernel.exception` listeners leaking stack traces, env vars, or internal hostnames in the response body.
            - Subscribers calling `Process` / making HTTP requests with values from the event (SSRF via event payload).
            - Listeners with side effects (DB write, mailer send) NOT wrapped in a Doctrine transaction or messenger envelope — request fails mid-way, state diverges.
            - Doctrine `postLoad` / `postFlush` events writing user-derived fields back without escaping (stored XSS, log injection).
            Do NOT flag:
            - Subscribers using `$event->setResponse()` to short-circuit — that is the documented kernel.controller pattern.
            - Listeners calling `LoggerInterface::info()` with structured arrays — not log injection unless raw `$_REQUEST` is interpolated.
            </skills>
            SKILL,
        ProjectFileType::NORMALIZER->value => <<<'SKILL'
            <skills role="normalizer">
            Hunt:
            - `denormalize()` building an Entity from request payload with `'allow_extra_attributes' => true` (mass-assignment) or without `'attributes' => [...]` allowlist.
            - `denormalize()` calling private setters via reflection / `ObjectNormalizer` ignoring `#[Ignore]` on sensitive fields (`roles`, `passwordHash`, `isAdmin`).
            - `normalize()` leaking sensitive fields by default (no `groups`, no `ignored_attributes`) — API leaks password hashes, tokens, internal ids.
            - `supportsDenormalization()` returning `true` for `object` or untyped data — gadget-chain entry point.
            - Custom denormalizer using `unserialize()` to decode a transport field.
            - `getSupportedTypes()` returning `'*'` widely — denormalizer steals control from safer normalizers downstream.
            Do NOT flag:
            - `Symfony\Component\Serializer\Normalizer\PropertyNormalizer` without `setIgnoredAttributes()` when the model has only safe public properties.
            - Normalizers operating purely on read-only DTOs with no setters.
            </skills>
            SKILL,
        ProjectFileType::SCHEDULER->value => <<<'SKILL'
            <skills role="scheduler">
            Hunt:
            - `#[AsSchedule]` / `ScheduleProviderInterface::getSchedule()` registering tasks that read user-input from DB and pass it unsanitized to `Process` / shell.
            - Cron-like schedules invoking privileged operations (mass email, payout, account deletion) without an audit log or kill-switch.
            - Tasks with no lock (`LockableTrait`, `LockFactory`) — overlapping runs cause duplicate billing or double notifications.
            - Schedules running with `RunCommandMessage` whose `command` string is built from user input — RCE via the schedule.
            - Recurring tasks fetching remote URLs (`HttpClient::request($urlFromDb)`) without a host allowlist (SSRF).
            Do NOT flag:
            - `RecurringMessage::every('1 hour', $message)` with a statically-typed message class and no user input.
            - Schedules using `LockableTrait` with a project-unique lock name.
            </skills>
            SKILL,
        ProjectFileType::VOTER->value => <<<'SKILL'
            <skills role="voter">
            Hunt:
            - `supports($attribute, $subject)` mismatched with attributes consumers actually pass (typo → silent allow).
            - `voteOnAttribute()` default branch returning `true` or implicit fallthrough — critical bypass.
            - Over-broad role shortcuts (`ROLE_SUPER_ADMIN` always allowed) without auditable trail.
            - Ownership checks with nullable / weak-typed comparisons (`==` on UUID strings, missing user object check).
            - Voters consulting only `getRoles()` while the request requires per-resource attribute checks.
            Do NOT flag:
            - Voters that explicitly `return false` as the default — that is the secure-by-default pattern.
            - Voters using `Security::isGranted('ROLE_USER')` after a positive ownership check.
            </skills>
            SKILL,
        ProjectFileType::ENTITY->value => <<<'SKILL'
            <skills role="entity">
            Hunt:
            - Lifecycle callbacks (`#[PrePersist]`, `#[PreUpdate]`) calling unsanitized methods, command execution, or external HTTP.
            - Public setters on sensitive fields (`isAdmin`, `roles`, `passwordHash`) exposed via form normalization.
            - Custom Doctrine types using `convertToPHPValue` with `unserialize` or `eval`-equivalent.
            - DQL/QueryBuilder usage with string concatenation of request input — even inside the entity class.
            - Boolean / enum coercion via Doctrine type juggling that lets attacker promote a role string.
            - Serializer groups: `#[Groups([...])]` (or `@Groups({...})`) that places a privileged field (`roles`, `isAdmin`, `passwordHash`, `apiToken`, `internal*`) into a write-side group (e.g. `user:write`, `*:write`, `admin:*`) — denormalization will set it from request payload. Report as `over_permissive_serializer_group`.
            - Read-side groups (`*:read`, `public`) leaking sensitive fields (`passwordHash`, `tokens`, internal ids) when the entity is serialized in API responses — also `over_permissive_serializer_group`.
            Do NOT flag:
            - Public setters on non-sensitive fields (titles, descriptions) where the form `mapped: false` or constraints validate input.
            - `#[ORM\Column]` with `nullable: true` — nullability is a schema concern, not a security one.
            - Read-only groups on safe fields (display name, public bio) — non-sensitive read groups are by design.
            - Fields annotated `#[Ignore]` / `#[SerializedName]` redirecting to a public alias — those are explicit safe overrides.
            </skills>
            SKILL,
        ProjectFileType::REPOSITORY->value => <<<'SKILL'
            <skills role="repository">
            Hunt:
            - DQL/SQL injection via string concatenation in custom finder methods; absence of `setParameter()`.
            - Dynamic `ORDER BY` / `LIMIT` fed from request input — Doctrine does NOT parameterize these.
            - `NativeQuery` / `getConnection()->executeQuery()` with interpolated user input.
            - Methods exposing arbitrary criteria (`findBy(['role' => $userInput])`) where caller forgot to constrain values.
            - Subquery building that bypasses voters/filters applied at the controller layer.
            Do NOT flag:
            - QueryBuilder calls that use `setParameter()` for every user-controlled value — Doctrine binds those safely.
            - `findOneBy([...])` / `findAll()` on non-sensitive entities; access control belongs to the voter, not the repository.
            </skills>
            SKILL,
        ProjectFileType::FORM->value => <<<'SKILL'
            <skills role="form">
            Hunt:
            - `'csrf_protection' => false` on forms processing state changes (acceptable only for stateless APIs with their own auth).
            - `'allow_extra_fields' => true` enabling mass assignment of unmapped properties via setters.
            - `EntityType` choice queries unscoped by ownership — attacker can select any other tenant's row.
            - Data transformers that `unserialize` / `json_decode` raw input without strict mode.
            - Missing `'constraints'` on free-form fields that flow into the database or shell.
            Do NOT flag:
            - Forms with the default CSRF token (Symfony enables it by default — only explicit `false` is the smell).
            - Fields declared `mapped: false` and re-validated by a constraint — those don't reach the entity setter.
            </skills>
            SKILL,
        ProjectFileType::TEMPLATE->value => <<<'SKILL'
            <skills role="template">
            Hunt:
            - `|raw` filter applied to variables originating from user input or untrusted DB content.
            - `autoescape` overridden to `false` or to a context that does not match the surrounding HTML/JS/URL context.
            - `{{ include(user_input) }}` or `{% include %}` with dynamic template names — SSTI vector.
            - `{% sandbox %}` / `{% apply %}` blocks lifting restrictions on user-supplied template fragments.
            - Inline JavaScript context (`<script>var x = {{ value }};`) without `|json_encode` — XSS via Twig.
            - URL attributes (`href`, `src`) built from user input without `|url_encode` and protocol whitelist (javascript:, data:).
            - Twig Components (`<twig:Component …/>`) passing user input through `data-*` attributes without escaping (`<twig:UserCard name="{{ name|raw }}"/>`).
            - Live Components emitting `data-live-action-param` / `data-live-prop` with untrusted values — bound back to the server unchecked.
            Do NOT flag:
            - Default `{{ value }}` interpolation — Twig auto-escapes for the active context.
            - `|raw` on values originating from a `Markdown` / `Sanitize` (HtmlSanitizer) transformation upstream — trust the sanitizer unless evidence shows otherwise.
            - `{% component %}` / `<twig:…/>` with statically-typed props in a `LiveComponent` whose writable props are constrained by validators.
            </skills>
            SKILL,
        ProjectFileType::CONFIG->value => <<<'SKILL'
            <skills role="config">
            Hunt:
            - Hardcoded secrets, API keys, DSNs (look for `_KEY`, `_SECRET`, `_TOKEN`, `password:`, full DSN strings).
            - `security.firewalls` with `security: false` on protected paths, or `access_control` rules with overly broad path patterns.
            - `framework.session.cookie_secure: false` / `cookie_samesite: none` / missing `cookie_httponly` in non-test envs.
            - Dev-only routes (`_profiler`, `_wdt`) not gated by environment or IP allowlist.
            - `cors.allow_origin: '*'` combined with `allow_credentials: true` — credential leak.
            - Exposed services with public `true` that wrap dangerous primitives (filesystem, process, raw SQL).
            - `framework.rate_limiter` absent for login / password-reset / API endpoints declared elsewhere.
            - `framework.messenger.transports.*.serializer: 'php_serialize'` or any class implementing `SerializerInterface` that calls `unserialize` on dequeued payloads.
            - `framework.webhook` declared without an HMAC secret env var or with the secret committed in plaintext.
            - `framework.lock` not configured for routes that perform balance-affecting operations.
            - `framework.html_sanitizer` set with `allowAllStaticAttributes()` or wide `allowElement()` lists — XSS via "sanitized" output.
            - `framework.http_client.scoped_clients.*.verify_peer: false` / `verify_host: false` — MITM exposure.
            - `messenger.routing` directing privileged commands to a transport with `failure_transport: null` — silent loss of audit trail.
            Do NOT flag:
            - Environment-variable references like `%env(DATABASE_URL)%` — those are externalized, not hardcoded.
            - `_profiler` / `_wdt` declarations gated by `when@dev` / `when@test`.
            - `framework.messenger.transports.*.serializer: messenger.transport.symfony_serializer` — the safe default.
            </skills>
            SKILL,
        ProjectFileType::PHP->value => <<<'SKILL'
            <skills role="php">
            Hunt:
            - Symfony ExpressionLanguage / Security Expression evaluating strings derived from user input.
            - `HttpClientInterface` calls with user-controlled URL or host — SSRF; check for protocol & host allowlist; `max_redirects` not bounded + redirect host not re-validated.
            - `unserialize()` / `igbinary_unserialize()` on untrusted payloads (cache values, queue messages, request body).
            - `Process` / `proc_open` / `shell_exec` constructed with user input concatenation; no `escapeshellarg`.
            - PSR-3 logger sinks receiving raw request payloads without redaction (log injection, log forging).
            - Cryptography: `md5`/`sha1` for security purposes, `random_int` vs `rand`/`mt_rand`, hardcoded IVs/keys.
            - `MailerInterface::send()` with `Email::from($userInput)` / `subject($userInput)` / `addBcc($userInput)` — header injection via newline in user data.
            - `CacheInterface::get($key, ...)` where `$key` is derived from request input without normalization — cache poisoning / cross-tenant leak.
            - `CacheItemPoolInterface` reads writing user-derived payloads then trusting them on subsequent reads (poisoned cache → privilege bypass).
            - `LockFactory::createLock()` missing on critical sections (refund, balance mutation, idempotent webhook) — race condition.
            - `HtmlSanitizerInterface::sanitize()` configured with `allowElement('script')` / `allowAttribute('on*')` — sanitizer disarmed.
            - `RateLimiterFactory::create($key)` with `$key` constant (`'global'`) instead of per-user/per-IP — limiter trivially exhausted.
            - PSR-16 / PSR-6 store handing back unserialized objects when the cache backend was filled with user input.
            Do NOT flag:
            - `md5`/`sha1` on non-security data (cache keys, ETags, file fingerprints) — those are integrity, not authentication.
            - `Process` invocations with hardcoded argument arrays (`new Process(['ls', '-la'])`) — no shell interpolation occurs.
            - `HttpClient::request()` against `%env(INTERNAL_SERVICE_URL)%` — that is an externally-configured trusted host, not SSRF.
            </skills>
            SKILL,
    ];

    /**
     * @param list<ProjectFile> $files
     */
    #[Override]
    public function buildSystemPrompt(array $files = []): string
    {
        $base = $this->basePrompt();

        $skills = $this->skillsForFiles($files);

        if ('' === $skills) {
            return $base;
        }

        return \sprintf("%s\n\n%s", $base, $skills);
    }

    /**
     * @param list<ProjectFile> $files
     */
    #[Override]
    public function buildUserMessage(array $files, SymfonyMapping $symfonyMapping): string
    {
        $context = NumberedFileContextRenderer::render($files);
        $summary = $symfonyMapping->toSummary();

        $noVoterList = implode("\n", array_map(
            static fn (ProjectFile $projectFile): string => '  - '.$projectFile->relativePath(),
            $symfonyMapping->controllersWithoutVoters(),
        ));

        $accessControlMap = SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);
        $voterCoverage = SymfonyMappingContextRenderer::renderVoterCoverage($symfonyMapping);
        $formBindings = SymfonyMappingContextRenderer::renderFormBindings($symfonyMapping);
        $closingInstruction = $this->closingInstruction();

        return <<<PROMPT
            ## Project Mapping Summary
            {$summary}

            ## Controllers WITHOUT Security Annotations (High Priority)
            {$noVoterList}

            {$accessControlMap}{$voterCoverage}{$formBindings}## Source Code
            Analyze these files for exploitable vulnerabilities. Each line is prefixed with its line number (`NNN | code`) — use those exact numbers when populating `line_start` and `line_end`; do NOT count manually or guess.

            {$context}

            {$closingInstruction}
            PROMPT;
    }

    private function closingInstruction(): string
    {
        if ($this->useStructuredCollection) {
            return 'Record every vulnerability you find via the `record_vulnerability` tool — one call per finding.';
        }

        return 'Return a JSON array of all vulnerabilities found.';
    }

    private function basePrompt(): string
    {
        return $this->basePromptIntro()
            .$this->outputFormatSection()
            .$this->severityAndConfidenceRubrics()
            .$this->fileNumberingAndScope()
            .$this->analysisMethodology()
            .$this->exampleFinding()
            .$this->rulesAndToolDiscipline();
    }

    private function basePromptIntro(): string
    {
        return <<<'PROMPT'
            You are an elite offensive security researcher and red team expert specializing in Symfony and PHP applications.
            Your mission is to think like a sophisticated attacker and find REAL, EXPLOITABLE vulnerabilities.

            You have deep expertise in:
            - Symfony internals (7.x/8.x): Voters, Authenticators, EventListeners, Forms, Serializer, Security component, Messenger, Webhook, Schedule, RateLimiter, Lock, HtmlSanitizer
            - PHP deserialization gadget chains
            - Doctrine ORM injection patterns (DQL injection, query builder abuse)
            - Twig SSTI (Server Side Template Injection) and Twig Components / Live Components vectors
            - Symfony routing and access control bypass patterns (firewall rules, access_control, voters)
            - Business logic and workflow exploitation
            - Mass assignment via Symfony Forms, ParamConverter, `#[MapRequestPayload]`, Serializer denormalizers
            - CSRF token bypass techniques specific to Symfony
            - Broken Voters and missing denyAccessUnlessGranted() calls
            - Complex multi-step injection paths through service chains
            - Messenger transports: PHP serializer abuse, missing idempotency, replay attacks via queues
            - Webhook signature verification gaps (HMAC, timing-attack via `==`/`===`, replay protection)
            - OAuth/OIDC handlers, AccessTokenHandler audience/issuer/signature gaps, `state`/PKCE bypass
            - Custom Authenticator failure modes: `SelfValidatingPassport` misuse, `supports()` returning null
            - Cache poisoning, mailer header injection, rate-limiter scope confusion


            PROMPT;
    }

    private function outputFormatSection(): string
    {
        if ($this->useStructuredCollection) {
            return <<<'PROMPT'
                Your output MUST be expressed via `record_vulnerability` tool calls — one call per finding. The platform validates each call against the tool's input schema, so malformed shapes (bare strings, env names, wrapper objects) cannot be emitted. Do NOT emit JSON arrays, prose listings, or any text-based enumeration of findings.
                Each tool call accepts these arguments (the input schema is authoritative):
                  type:            one of the valid vulnerability type values
                  severity:        critical | high | medium | low | info
                  title:           short headline
                  description:     detailed technical description (required)
                  file_path:       project-relative path (required)
                  line_start:      first line number from the NNN | prefix
                  line_end:        last line number (= line_start for single-line findings)
                  vulnerable_code: the actual vulnerable code snippet
                  attack_vector:   step-by-step exploitation path
                  proof:           concrete proof of concept or payload
                  remediation:     specific fix with code example
                  confidence:      0.0-1.0 float


                PROMPT;
        }

        return <<<'PROMPT'
            Your output must be a valid JSON array of vulnerability objects.
            Each object must have:
            {
              "type": "<vulnerability_type_value>",
              "severity": "<critical|high|medium|low|info>",
              "title": "<short title>",
              "description": "<detailed technical description>",
              "file_path": "<relative/path/to/file.php>",
              "line_start": <integer>,
              "line_end": <integer>,
              "vulnerable_code": "<the actual vulnerable code snippet>",
              "attack_vector": "<how an attacker would exploit this step by step>",
              "proof": "<concrete proof of concept or payload>",
              "remediation": "<specific fix with code example>",
              "confidence": <0.0-1.0 float>
            }


            PROMPT;
    }

    private function severityAndConfidenceRubrics(): string
    {
        return <<<'PROMPT'
            Valid type values:
            sql_injection, command_injection, ldap_injection, xpath_injection, twig_injection, header_injection,
            broken_access_control, missing_voter, voter_bypass, role_escalation, insecure_direct_object_reference,
            missing_csrf_protection, business_logic_flaw, race_condition, insecure_workflow, price_manipulation,
            state_machine_bypass, mass_assignment, insecure_deserialization, unsafe_parameter_binding,
            exposed_internal_service, misconfigured_firewall, insecure_redirect, sensitive_data_exposure,
            log_injection, path_traversal, ssrf, xxe, open_redirect, weak_cryptography, insecure_random,
            hardcoded_secret, missing_signature_verification, messenger_handler_unsafe, missing_rate_limiting,
            cache_poisoning, mailer_header_injection, webhook_replay, authenticator_bypass,
            over_permissive_serializer_group

            Severity rubric (calibrate every finding against this scale — do NOT inflate severity for emphasis):
            - critical: unauthenticated RCE, full authentication bypass, mass data exfiltration without auth, hardcoded production secret in a committed file.
            - high: authenticated RCE, privilege escalation across tenants, IDOR exposing PII, SQL/DQL injection with a reachable sink, voter bypass on sensitive resources.
            - medium: stored XSS in authenticated views, CSRF on state-changing actions, SSRF reaching internal services, weak crypto guarding non-public secrets.
            - low: reflected XSS in low-impact contexts, information disclosure of non-sensitive metadata, weak crypto on already-public data, missing security headers.
            - info: defense-in-depth opportunities, hardening suggestions, deprecated patterns with no current exploit path.

            Exposure weighting: severity is risk (roughly likelihood times impact), not bug class alone. Raise severity when the vulnerable path is reachable by an unauthenticated or low-privilege actor (public route, anonymous firewall, pre-auth handler, webhook); lower it when reachable only behind strong authentication or by trusted/admin roles. Weigh exploitability and the sensitivity of the affected data rather than a generic CVSS guess.

            Confidence rubric (filtered downstream — entries below 0.6 are dropped before reviewer):
            - 0.9-1.0: tainted source traced to dangerous sink with concrete payload.
            - 0.7-0.89: clear vulnerable pattern matched, exploitation plausible without a full PoC.
            - 0.6-0.69: pattern smell that needs reviewer adjudication.
            - Below 0.6: do NOT report — it will be filtered and waste reviewer budget.


            PROMPT;
    }

    private function fileNumberingAndScope(): string
    {
        return <<<'PROMPT'
            File-numbering protocol:
            Each line of every source file is prefixed with `NNN | ` (line number, space, pipe, space). Populate `line_start` / `line_end` using those exact numbers — never count or estimate. If a finding spans a single line, set `line_end == line_start`.

            Scope:
            - Only report findings in the source files provided below. Ignore code under `vendor/`, `var/cache/`, `var/log/`, any path containing `.generated.` or `.cache.`, and obvious build artifacts.
            - If a finding references code outside the provided chunk, set `confidence` no higher than 0.7 and explain the cross-file dependency in `attack_vector`.


            PROMPT;
    }

    private function analysisMethodology(): string
    {
        return <<<'PROMPT'
            Analysis methodology — apply to every candidate before recording it:
            - Source (trust boundary): identify the attacker-controlled entry point the value crosses from — route/path parameter, query string, request body, header, cookie, uploaded file, or webhook/queue payload (and anything derived from them).
            - Flow: trace that value through each assignment, transformation, and cross-file call to the sink, noting any sanitizer, validator, parameterized query, escaping, or access-control check on the path.
            - Sink: confirm it reaches a dangerous operation (SQL/DQL, shell/process, file path, Twig, redirect, deserialization, reflected/stored output, or a privileged state change) with no mitigating control in between.
            - Verify before recording: record ONLY when the value is genuinely attacker-controlled, reaches the sink on a reachable path, and nothing on the path (guard clause, validator, parameterization, escaping, `access_control`, voter) neutralizes it. Otherwise do not record — or lower `confidence` and state the missing link in `attack_vector`. Always name the concrete source, sink, and path.

            For each entry point, sweep the STRIDE categories so no class is skipped:
            - Spoofing: authentication or identity-check bypass (authenticator flaws, forgeable or replayable tokens).
            - Tampering: mass assignment, unvalidated writes, parameter binding to privileged fields.
            - Repudiation: privileged or balance-affecting actions with no audit trail or idempotency key.
            - Information disclosure: IDOR, over-permissive serializer groups, verbose errors, sensitive data in logs.
            - Denial of service: unbounded loops/uploads/recursion, missing rate limiting on costly or auth endpoints.
            - Elevation of privilege: missing `#[IsGranted]` / `denyAccessUnlessGranted()`, broken voter, role escalation.


            PROMPT;
    }

    private function exampleFinding(): string
    {
        if ($this->useStructuredCollection) {
            return <<<'PROMPT'
                Example finding (illustrative — do NOT echo this in your output):
                Input file `src/Controller/InvoiceController.php`:
                  42 |     public function show(int $id, InvoiceRepository $repo): Response
                  43 |     {
                  44 |         $invoice = $repo->find($id);
                  45 |         return $this->render('invoice/show.html.twig', ['invoice' => $invoice]);
                  46 |     }
                Expected behavior: call `record_vulnerability` once with arguments equivalent to:
                  type=insecure_direct_object_reference, severity=high,
                  title="IDOR on invoice show action",
                  description="The show() action fetches an Invoice by id without verifying that the current user owns it. Any authenticated user can view any invoice by changing the path parameter.",
                  file_path="src/Controller/InvoiceController.php", line_start=42, line_end=46,
                  vulnerable_code="$invoice = $repo->find($id);",
                  attack_vector="1. Authenticate as user A. 2. Browse to /invoice/{B's invoice id}. 3. Server returns the invoice without ownership check.",
                  proof="GET /invoice/9999 → 200 with another tenant's invoice payload.",
                  remediation="Add `\$this->denyAccessUnlessGranted('VIEW', \$invoice);` after fetch, or query the repository scoped to `\$this->getUser()`.",
                  confidence=0.9.


                PROMPT;
        }

        return <<<'PROMPT'
            Example finding (illustrative — do NOT echo this in your output):
            Input file `src/Controller/InvoiceController.php`:
              42 |     public function show(int $id, InvoiceRepository $repo): Response
              43 |     {
              44 |         $invoice = $repo->find($id);
              45 |         return $this->render('invoice/show.html.twig', ['invoice' => $invoice]);
              46 |     }
            Expected JSON entry:
            {
              "type": "insecure_direct_object_reference",
              "severity": "high",
              "title": "IDOR on invoice show action",
              "description": "The show() action fetches an Invoice by id without verifying that the current user owns it. Any authenticated user can view any invoice by changing the path parameter.",
              "file_path": "src/Controller/InvoiceController.php",
              "line_start": 42,
              "line_end": 46,
              "vulnerable_code": "$invoice = $repo->find($id);",
              "attack_vector": "1. Authenticate as user A. 2. Browse to /invoice/{B's invoice id}. 3. Server returns the invoice without ownership check.",
              "proof": "GET /invoice/9999 → 200 with another tenant's invoice payload.",
              "remediation": "Add `$this->denyAccessUnlessGranted('VIEW', $invoice);` after fetch, or query the repository scoped to `$this->getUser()`.",
              "confidence": 0.9
            }


            PROMPT;
    }

    private function rulesAndToolDiscipline(): string
    {
        if ($this->useStructuredCollection) {
            return <<<'PROMPT'
                Rules:
                - ONLY report REAL vulnerabilities with clear exploitation paths
                - Do NOT report theoretical issues without concrete evidence in the code
                - Focus on issues traditional SAST tools miss: business logic, context-dependent access control
                - Consider the FULL call chain, not just single function calls
                - Cross-reference controllers, voters, services, and entities together
                - Record findings ONLY by calling the `record_vulnerability` tool — one call per finding. Do NOT emit prose, JSON, or any other listing of findings.
                - When no vulnerabilities are found, call no tools and finish with an empty response. NEVER call `record_vulnerability` with a placeholder, label, environment name, or "no findings" payload.

                Tool Usage Discipline:
                - You have a LIMITED, finite tool-call budget per chunk. Do NOT call `record_vulnerability` speculatively — only when you have concrete evidence of an exploitable finding.
                - The moment you have decided on the complete set of findings, stop calling tools and finish your turn. Continuing "to be thorough" wastes the budget.
                - If your scan of the provided files surfaces no exploitable findings, finish immediately with no tool calls.
                PROMPT;
        }

        return <<<'PROMPT'
            Rules:
            - ONLY report REAL vulnerabilities with clear exploitation paths
            - Do NOT report theoretical issues without concrete evidence in the code
            - Focus on issues traditional SAST tools miss: business logic, context-dependent access control
            - Consider the FULL call chain, not just single function calls
            - Cross-reference controllers, voters, services, and entities together
            - Return ONLY the JSON array, no prose, no markdown fences
            - Every element of the JSON array MUST be a vulnerability object of the exact shape above. NEVER emit a bare string, number, boolean, or null as an array element. When no vulnerabilities are found, return `[]` — never `["no findings"]`, `["safe"]`, or any prose substitute.
            - The top-level value MUST be a JSON array (`[...]`). NEVER wrap findings in an object such as `{"vulnerabilities": [...]}`, `{"findings": [...]}`, `{"dev": [...], "test": [...]}`, or any environment-keyed map. If you want to indicate which environment a finding applies to, put that information inside the `description` or `attack_vector` field of the vulnerability object — never as a separate array element or wrapper key.
            - Environment names, group names, role names, and other short identifiers (`"dev"`, `"test"`, `"prod"`, `"local"`, `"staging"`, `"ROLE_USER"`, …) extracted from the analyzed source code are NEVER valid array elements. Forbidden shape: `["dev", "test", {...vulnerability...}]`. Required shape: `[{...vulnerability...}]` — mention the environment inside the object's text fields instead.

            Tool Usage Discipline:
            - You have a LIMITED, finite tool-call budget per chunk. Do NOT gather evidence indefinitely — once you have enough to decide, stop using tools and emit the final JSON answer.
            - The moment you have sufficient evidence (either confirming a finding or ruling one out), STOP calling tools and produce the JSON. Continuing "to be thorough" wastes the budget and risks running out before you can answer.
            - If your initial scan of the provided files surfaces no exploitable findings, emit `[]` immediately. Do NOT keep calling tools hunting for something that is not there.
            - Once you have decided to answer, your response MUST contain ONLY the JSON array — no prose, no reasoning, no further tool calls. Any deviation (additional tool calls after the decision, explanatory text, partial JSON) causes the response to be discarded as malformed.
            PROMPT;
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function skillsForFiles(array $files): string
    {
        $presentTypes = array_map(
            static fn (ProjectFile $projectFile): ProjectFileType => $projectFile->fileType(),
            $files,
        );

        $blocks = [];
        foreach (self::SKILL_PRIORITY as $type) {
            if ($this->emitAllSkills || \in_array($type, $presentTypes, true)) {
                $blocks[] = self::SKILLS[$type->value];
            }
        }

        return implode("\n\n", $blocks);
    }
}
