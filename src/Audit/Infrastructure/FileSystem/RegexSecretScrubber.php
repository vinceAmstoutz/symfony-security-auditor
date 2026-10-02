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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

use Override;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SecretPatternLabel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;

/**
 * Replaces credential-shaped strings in file content with redacted placeholders.
 *
 * The pattern set covers common high-signal leaks: cloud provider keys, version-control
 * tokens, payment processor keys, generic credential assignments, JWT-shaped tokens,
 * PEM-encoded private keys, env-style token assignments, connection-string URIs with
 * embedded credentials (e.g. `postgres://user:pass@host`), `Authorization: Bearer` and
 * `Authorization: Basic` headers,
 * OpenAI-style `sk-`/`sk-proj-` keys, Slack incoming webhook URLs, and GitLab, Hugging Face,
 * npm, SendGrid and PyPI tokens. Each match is replaced
 * with `***REDACTED:<label>***` so downstream prompt builders can still emit a coherent
 * file context without exposing the secret to the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RegexSecretScrubber implements SecretScrubberInterface
{
    /**
     * A credential word glued to a known qualifier (`APIKEY`, `SECRETKEY`,
     * `DBPASS`, `PGPASSWORD`) names a credential as surely as its underscored
     * spelling; the qualifier list keeps `MONKEY`, `TURKEY` or `COMPASS` out.
     */
    private const string GLUED_ENV_CREDENTIAL_KEY = '(?:API|APP|AUTH|ACCESS|SECRET|PRIVATE|CLIENT|MASTER|ACCOUNT|SIGNING|ENCRYPTION|JWT|OAUTH|SESSION|REFRESH|BEARER|PASS|DB|DATABASE|ROOT|ADMIN|USER|MYSQL|POSTGRES|PG|MONGO|REDIS|SMTP|MAIL|FTP|SSH)+(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|PASS)';

    /**
     * A quoted fragment joined to a variable or a call: `'" . $pass . "'`.
     */
    private const string CONCATENATED_CODE = '/["\']\s*\.\s*(?:\$[A-Za-z_]|[a-z_]\w*\s*\()|(?:\$[A-Za-z_]\w*|\))\s*\.\s*["\']/';

    /**
     * The first word of an unquoted value, shaped the way only PHP code is: a
     * variable followed by an access (`$request->`, `$_GET[`) or ending there
     * (`$plain,`), a class constant (`self::DEFAULT_SECRET`, `Foo::BAR;`), or a
     * call — static or a lower-case function — that ends the statement
     * (`uniqid();`, `mt_rand(1000,`) or opens on a string, a variable or
     * another call (`hash_hmac('sha256',`). `$2y$13$…`, `summer(2024)`,
     * `abc('x')yz` or `P4ss::WORD_1` match none of them.
     */
    private const string PHP_EXPRESSION = '/^(?:\$[A-Za-z_]\w*(?:[;,]?$|->|\?->|::|\[)|(?:self|static|parent)::[A-Z_][A-Z0-9_]*[;,]?$|[A-Z]\w*::[A-Z_][A-Z0-9_]*[;,]$|(?:\\\\?[a-z_]\w*|(?:self|static|parent|[A-Z]\w*)::[A-Za-z_]\w*)\((?:(?:[\'"$]|[a-z_]\w*\().*[,;()]|.*[;,])$)/';

    private const string INLINE_CREDENTIAL_KEY = '(?:password|passwd|pwd|passphrase|(?<![a-z])pass(?![_-])|secret|credentials|api[_-]?key|api[_-]?token|api[_-]?secret|access[_-]?token|access[_-]?key|auth[_-]?token|auth[_-]?key|client[_-]?secret|private[_-]?key|account[_-]?key|secret[_-]?key|app[_-]?key|app[_-]?secret|master[_-]?key|signing[_-]?key|encryption[_-]?key|session[_-]?secret|jwt[_-]?secret|refresh[_-]?token|bearer[_-]?token|(?:db|database|root|admin|user|mysql|postgres|pg|mongo|redis|smtp|mail|ftp|ssh)[_-]?pass(?:word|wd)?)';

    /**
     * @var array<string, string>
     */
    private array $patterns;

    /**
     * @param list<string> $additionalPatterns extra PCRE patterns merged with the defaults.
     *                                         Each pattern is given a synthetic label
     *                                         `custom_<index>` for redaction reporting.
     *
     * @throws SecretScrubberConfigurationException
     */
    public function __construct(
        array $additionalPatterns = [],
        private LoggerInterface $logger = new NullLogger(),
    ) {
        $patterns = $this->defaultPatterns();
        foreach ($additionalPatterns as $index => $pattern) {
            $error = $this->validatePattern($pattern);
            if (null !== $error) {
                throw SecretScrubberConfigurationException::forInvalidPattern($pattern, $error);
            }

            $patterns[\sprintf('custom_%s', $index)] = $pattern;
        }

        $this->patterns = $patterns;
    }

    /**
     * The quantifiers are possessive (`*+`, `{4,}+`): `\\.` and `(?!\2)[^\n]`
     * both match a bare backslash, so a backtracking quantifier would let an
     * unterminated, backslash-heavy value elsewhere in the file exhaust
     * `pcre.backtrack_limit` and silently skip redaction file-wide. A quoted
     * value runs to `(?!\2)[^\n]` rather than excluding both quote characters,
     * so a value quoted with one type may hold the other — "don't" inside
     * double quotes — without the closing-quote backreference stopping there.
     *
     * @return array<string, string> map of pattern label => PCRE pattern. Labels are stable
     *                               and appear in the redaction placeholder.
     */
    private function defaultPatterns(): array
    {
        return [
            SecretPatternLabel::AwsAccessKey->value => '/\bAKIA[0-9A-Z]{16}\b/',
            SecretPatternLabel::GithubToken->value => '/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_\w{22,255})\b/',
            SecretPatternLabel::StripeKey->value => '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/',
            SecretPatternLabel::SlackToken->value => '/\b(?:xox[abprs]-[A-Za-z0-9-]{10,72}|xapp-[0-9]-[A-Za-z0-9-]{10,120})\b/',
            SecretPatternLabel::GoogleApiKey->value => '/\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])/',
            SecretPatternLabel::Jwt->value => '/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/',
            SecretPatternLabel::PemPrivateKey->value => '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/',
            SecretPatternLabel::ConnectionUri->value => '~\b([a-z][a-z0-9+.\-]*://)[^:@/\s]*:[^/\s]+@~i',
            SecretPatternLabel::EnvAssignment->value => \sprintf('/((?:^|\s)(?:[A-Z][A-Z0-9]*_)*(?:(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|KEY|DSN)(?:_[A-Z0-9]+)*|%s(?:_[A-Z0-9]+)*|PASS|PW))\s*=[ \t]*(?!\s*\n)(?:(["\'])(?:\\\\.|(?!\2)[^\n])*+\2|\S+)/m', self::GLUED_ENV_CREDENTIAL_KEY),
            SecretPatternLabel::InlineAssignment->value => \sprintf('/(["\']?%s(?:[_-][a-z0-9]+)*["\']?\s*(?:=>|[:=])[ \t]*)(?!\*\*\*REDACTED:)(?:(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2|([^"\'\s]\S{3,}(?:[ \t]+[A-Za-z0-9]+)*))/i', self::INLINE_CREDENTIAL_KEY),
            SecretPatternLabel::MultilineAssignment->value => \sprintf('/(["\']?%s(?:[_-][a-z0-9]+)*["\']?\s*(?:=>|[:=]))[ \t]*\r?\n[ \t]*(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2/mi', self::INLINE_CREDENTIAL_KEY),
            SecretPatternLabel::BearerToken->value => '/\bBearer\s+[A-Za-z0-9\-_.]{20,4096}\b/i',
            SecretPatternLabel::BasicAuthorization->value => '~\b((?:proxy-)?authorization\b["\']?\s*(?::|=>|=)\s*["\']?basic\s+)[A-Za-z0-9+/=_\-]{8,4096}~i',
            SecretPatternLabel::OpenAiApiKey->value => '/\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,200}\b/',
            SecretPatternLabel::SlackWebhookUrl->value => '~\bhttps://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+\b~',
            SecretPatternLabel::GitlabToken->value => '/\bgl(?:pat|ptt|rt|dt|ft|oas|soat|cbt|imt|agent)-[A-Za-z0-9_\-]{20,}/',
            SecretPatternLabel::HuggingFaceToken->value => '/\bhf_[A-Za-z0-9]{30,}\b/',
            SecretPatternLabel::NpmToken->value => '/\bnpm_[A-Za-z0-9]{36}\b/',
            SecretPatternLabel::SendgridApiKey->value => '/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/',
            SecretPatternLabel::PypiToken->value => '/\bpypi-Ag[A-Za-z0-9_\-]{50,}/',
        ];
    }

    #[Override]
    public function scrub(string $content): string
    {
        foreach ($this->patterns as $label => $pattern) {
            $result = match (SecretPatternLabel::tryFrom($label)) {
                SecretPatternLabel::InlineAssignment => preg_replace_callback($pattern, $this->redactInlineAssignment(...), $content),
                SecretPatternLabel::MultilineAssignment => preg_replace_callback($pattern, $this->redactMultilineAssignment(...), $content),
                SecretPatternLabel::PemPrivateKey => preg_replace_callback($pattern, $this->redactPreservingLineCount(...), $content),
                default => preg_replace($pattern, $this->replacementFor($label), $content),
            };

            if (null === $result) {
                return $this->withheldContent($label, $content);
            }

            $content = $result;
        }

        return $content;
    }

    /**
     * A pattern the PCRE engine refuses to evaluate — a file crafted to exhaust
     * `pcre.backtrack_limit`, a `/u` custom pattern meeting invalid UTF-8 — leaves
     * the content only part-scanned, and nothing downstream can tell that apart
     * from a clean scan. Enabling secret scrubbing is a promise that no credential
     * reaches the LLM, so the content is withheld rather than sent unverified.
     */
    private function withheldContent(string $label, string $content): string
    {
        $this->logger->warning('Withheld file content: a secret-scrubbing pattern could not be evaluated', [
            'pattern' => $label,
            'error' => preg_last_error_msg(),
        ]);

        return $this->placeholderPreservingLineCount(SecretPatternLabel::Unscannable, $content);
    }

    private function replacementFor(string $label): string
    {
        return match (SecretPatternLabel::tryFrom($label)) {
            SecretPatternLabel::EnvAssignment => \sprintf('$1=***REDACTED:%s***', $label),
            SecretPatternLabel::ConnectionUri => \sprintf('$1***REDACTED:%s***@', $label),
            SecretPatternLabel::BasicAuthorization => \sprintf('$1***REDACTED:%s***', $label),
            default => \sprintf('***REDACTED:%s***', $label),
        };
    }

    /**
     * A credential-named key is also a common variable, column or array key,
     * and the code around it is what the audit reads: a request parameter
     * flowing into `$pass`, or a `pass` column concatenated into a query, is a
     * finding redaction would hide. A value shaped like PHP code — a variable
     * access, a class constant, a call, or a quoted fragment joined to a
     * variable or a call — is left as written; any other value is redacted,
     * a literal holding `(`, `::` or a `$` included. A literal written in
     * exactly one of those shapes is read as code: that is the trade-off for
     * letting the audit see the code.
     */
    private function isCode(string $value, bool $quoted): bool
    {
        return $quoted
            ? 1 === preg_match(self::CONCATENATED_CODE, $value)
            : 1 === preg_match(self::PHP_EXPRESSION, explode(' ', strtr($value, "\t", ' '))[0]);
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactInlineAssignment(array $match): string
    {
        $quote = $match[2] ?? '';
        $value = ($match[3] ?? '').($match[4] ?? '');

        if ($this->isConfigPlaceholder($value) || $this->isCode($value, '' !== $quote)) {
            return $match[0];
        }

        return \sprintf('%s%s***REDACTED:%s***%s', $match[1], $quote, SecretPatternLabel::InlineAssignment->value, $quote);
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactMultilineAssignment(array $match): string
    {
        $quote = $match[2] ?? '';
        $value = $match[3] ?? '';

        if ($this->isConfigPlaceholder($value) || $this->isCode($value, true)) {
            return $match[0];
        }

        return \sprintf('%s%s%s***REDACTED:%s***%s', $match[1], str_repeat("\n", substr_count($match[0], "\n")), $quote, SecretPatternLabel::MultilineAssignment->value, $quote);
    }

    /**
     * Replaces a multi-line match (the PEM key block) with a single placeholder
     * line followed by enough blank lines to keep the file's total line count
     * unchanged — otherwise every subsequent line number the attacker/reviewer
     * reports would be off by the number of lines the key spanned.
     *
     * @param array<int|string, string> $match
     */
    private function redactPreservingLineCount(array $match): string
    {
        return $this->placeholderPreservingLineCount(SecretPatternLabel::PemPrivateKey, $match[0]);
    }

    private function placeholderPreservingLineCount(SecretPatternLabel $secretPatternLabel, string $replaced): string
    {
        return \sprintf('***REDACTED:%s***%s', $secretPatternLabel->value, str_repeat("\n", substr_count($replaced, "\n")));
    }

    /**
     * Detects Symfony parameter references (`%env(FOO)%`, `%kernel.secret%`) and shell-style
     * env expansions (`$FOO`, `${FOO}`). These are configuration indirections, not committed
     * secrets — redacting them produces a false positive when an LLM sees the placeholder
     * marker and reports an "inline credential" vulnerability for code that follows the
     * recommended Symfony secrets pattern.
     */
    private function isConfigPlaceholder(string $value): bool
    {
        return 1 === preg_match('/\A%[^%\s]+%\z/', $value)
            || 1 === preg_match('/\A\$\{?[A-Za-z_]\w*\}?\z/', $value);
    }

    private function validatePattern(string $pattern): ?string
    {
        if ('' === $pattern) {
            return 'empty pattern';
        }

        $error = null;
        set_error_handler(static function (int $severity, string $message) use (&$error): bool {
            $error = $message;

            return true;
        });

        $isValidPattern = false !== preg_match($pattern, '');
        restore_error_handler();

        return $isValidPattern ? null : ($error ?? preg_last_error_msg());
    }
}
