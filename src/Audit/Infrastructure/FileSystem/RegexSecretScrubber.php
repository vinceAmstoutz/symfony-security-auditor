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
 * PEM-encoded private keys and PGP private key blocks, env-style token assignments,
 * Symfony `env(NAME)` parameter defaults and XML `<parameter>` values, PHP `define()`
 * constants, connection-string URIs with
 * embedded credentials (e.g. `postgres://user:pass@host`), `Authorization: Bearer` and
 * `Authorization: Basic` headers,
 * OpenAI-style `sk-`/`sk-proj-` keys, Slack and Discord webhook URLs, and GitLab, Hugging Face,
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
    private const string GLUED_ENV_CREDENTIAL_KEY = '(?:API|APP|AUTH|ACCESS|SECRET|PRIVATE|CLIENT|MASTER|ACCOUNT|SIGNING|ENCRYPTION|JWT|OAUTH|SESSION|REFRESH|BEARER|PASS|DB|DATABASE|ROOT|ADMIN|USER|MYSQL|POSTGRES|PG|MONGO|REDIS|SMTP|MAIL|FTP|SSH){1,4}(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|PASS)';

    /**
     * A plain YAML scalar cannot start with `*`: a placeholder standing alone
     * as a mapping value, a list item or a flow entry is read as an alias and
     * fails the whole document, so it is quoted.
     */
    private const string UNQUOTED_YAML_PLACEHOLDER = '/([:\-][ \t]++)(\*\*\*REDACTED:[a-z0-9_]++\*\*\*)(?=[ \t]*+(?:[,})\]#]|\r?$))/m';

    /**
     * A closer that ends a YAML block entry is part of its plain scalar (`password: S3cr3t;`), so it is
     * redacted with the value instead of being left behind the quoted placeholder, where YAML cannot read it.
     */
    private const string YAML_ENTRY_ENDING_IN_CLOSERS = '/^([ \t]*+(?:-[ \t]++)?(?:"[\w.\-]++"|\'[\w.\-]++\'|[\w.\-]++):[ \t]++)(\*\*\*REDACTED:inline_assignment\*\*\*)[;:"\']++(?=(?:[ \t]++#[^\n]*)?\r?$)/m';

    private const string STATEMENT_CLOSERS = ';:,\'")]';

    private const int MINIMUM_SECRET_LENGTH = 4;

    /**
     * A DSN assignment whose value is a URL with no user part and no credential-named
     * parameter holds nothing to hide: `MAILER_DSN=null://null` or the stock
     * `MESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0`.
     */
    private const string CREDENTIAL_FREE_DSN_ASSIGNMENT = '(?:[A-Z][A-Z0-9]*_){0,8}DSN(?:_[A-Z0-9]+){0,8}\s*=[ \t]*["\']?[a-z][a-z0-9+.\-]{0,31}:\/\/(?![^\s"\'@?;]{0,256}+[?;][^\s"\'@]{0,256}(?i:auth|key|token|secret|pass|pwd|cred))[^@\s"\']{0,256}+(?:["\']|\s|\z)';

    private const string PRIVATE_KEY_LABEL = '(?:(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)';

    /**
     * A quoted fragment joined to a variable or a call: `'" . $pass . "'`.
     */
    private const string CONCATENATED_CODE = '/["\']\s*\.\s*(?:\$[A-Za-z_]|[a-z_]\w*\s*\()|(?:\$[A-Za-z_]\w*|\))\s*\.\s*["\']/';

    /**
     * The first word of an unquoted value, shaped the way only PHP code is: a
     * variable followed by an access (`$request->`, `$_GET[`) or ending there
     * (`$plain,`, `$plain)`), a class constant (`self::DEFAULT_SECRET`,
     * `Foo::BAR;`, `\PDO::ATTR_KEY`), a global one (`\OPENSSL_KEYTYPE_RSA,`),
     * an array opening on a variable, a string or a spread (`[$a, $b]`), a
     * negation of any of them, a parenthesised variable or instance
     * (`($a || $b)`, `(new Foo())`), a call nested in a call
     * (`unserialize(serialize(`), or a call — static or a lower-case function —
     * that ends the statement (`uniqid();`, `mt_rand(1000,`), closes an
     * argument list or an array (`getenv('X')]`) or opens on a string, a
     * variable or another call (`hash_hmac('sha256',`). `$2y$13$…`,
     * `summer(2024)`, `abc('x')yz` or `P4ss::WORD_1` match none of them.
     */
    private const string PHP_EXPRESSION = '/^!?(?:\$[A-Za-z_]\w*(?:[;,)\]]*$|->|\?->|::|\[)|(?:self|static|parent)::[A-Z_][A-Z0-9_]*[;,)\]]*$|[A-Z]\w*::[A-Z_][A-Z0-9_]*[;,)\]]+$|\\\\[A-Za-z_][\w\\\\]*(?:::[A-Za-z_]\w*)?[;,)\]]*$|\[(?:["\'$\]]|\.\.\.)|\((?:\$[A-Za-z_]|new$)|\\\\?[a-z_]\w*\([a-z_]\w*\(|(?:\\\\?[a-z_]\w*|(?:self|static|parent|[A-Z]\w*)::[A-Za-z_]\w*)\((?:(?:[\'"$]|[a-z_]\w*\().*[,;()\]]|.*[;,])$)/';

    private const string CREDENTIAL_WORDS = 'password|passwd|pwd|passphrase|secret|credentials|api[_-]?key|api[_-]?token|api[_-]?secret|access[_-]?token|access[_-]?key|auth[_-]?token|auth[_-]?key|client[_-]?secret|private[_-]?key|account[_-]?key|secret[_-]?key|app[_-]?key|app[_-]?secret|master[_-]?key|signing[_-]?key|encryption[_-]?key|session[_-]?secret|jwt[_-]?secret|refresh[_-]?token|bearer[_-]?token|(?:db|database|root|admin|user|mysql|postgres|pg|mongo|redis|smtp|mail|ftp|ssh)[_-]?pass(?:word|wd)?';

    private const string PURE_VALUE_FUNCTIONS = 'hex2bin|bin2hex|base64_decode|base64_encode|sodium_hex2bin|sodium_base642bin|password_hash|md5|sha1|trim|ltrim|rtrim|strtolower|strtoupper|urldecode|rawurldecode|urlencode|rawurlencode';

    private const string QUOTED_BODY_OF_GROUP_TWO = '((?:\\\\.|(?!\2)[^\n]){4,}+)';

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
     * A repeated group costs the engine a stack frame per repetition, so the
     * segments of a key are bounded (`{0,8}`, `{1,4}`) and the further words
     * of an unquoted value are one character run: a single line repeating
     * `_a` would otherwise exhaust the JIT stack and withhold the whole file.
     * A private key with no end marker after it ends the search, since no
     * later key can have one either, and a URL scheme is at most 32
     * characters, so neither rescans the rest of the file from every header
     * or word boundary.
     *
     * @return array<string, string> map of pattern label => PCRE pattern. Labels are stable
     *                               and appear in the redaction placeholder.
     */
    private function defaultPatterns(): array
    {
        $envCredentialName = $this->envCredentialName();
        $inlineCredentialKey = $this->inlineCredentialKey();
        $callCredentialName = \sprintf('(?:%s|token)', self::CREDENTIAL_WORDS);

        return [
            SecretPatternLabel::AwsAccessKey->value => '/\bAKIA[0-9A-Z]{16}\b/',
            SecretPatternLabel::GithubToken->value => '/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_\w{22,255})\b/',
            SecretPatternLabel::StripeKey->value => '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/',
            SecretPatternLabel::SlackToken->value => '/\b(?:xox[abprs]-[A-Za-z0-9-]{10,72}|xapp-[0-9]-[A-Za-z0-9-]{10,120})\b/',
            SecretPatternLabel::GoogleApiKey->value => '/\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])/',
            SecretPatternLabel::Jwt->value => '/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/',
            SecretPatternLabel::PemPrivateKey->value => \sprintf('/-----BEGIN %1$s-----(*COMMIT)[\s\S]*?-----END %1$s-----/', self::PRIVATE_KEY_LABEL),
            SecretPatternLabel::ConnectionUri->value => '~\b([a-z][a-z0-9+.\-]{0,31}://)[^:@/\s]*:[^/\s]+@~i',
            SecretPatternLabel::EnvAssignment->value => \sprintf('/((?:^|\s)(const\s+(?:[?\w\\\\|&]+\s+)?)?%s)(\s*=[ \t]*)(?!\s*\n)(?:(["\'])(?:\\\\.|(?!\4)[^\r\n])*+(?:\4|(?=\r?$))|\S+)/m', $envCredentialName),
            SecretPatternLabel::InlineAssignment->value => \sprintf('/(["\']?(?:%1$s(?:[_-][a-z0-9]+){0,8}["\']?\]?\s*(?:=>|:(?!:)|=)|env\(%2$s\)["\']?\s*:|define\(\s*["\']%2$s["\']\s*,)[ \t]*(?:\((?:string|int|integer|float|double|bool|boolean|array|object)\)[ \t]*)?+(?:\\\\?(?:%3$s)[ \t]*+\([ \t]*+(?=["\']))?)(?!\*\*\*REDACTED:)(?:(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2|([^"\'\s]\S{3,}(?:(?<![;:)\]\'"])(?:(?<!,)|(?![ \t]*+[\w-]++[ \t]*+:))(?:[ \t]*+[A-Za-z0-9]++)++)?))/i', $inlineCredentialKey, $envCredentialName, self::PURE_VALUE_FUNCTIONS),
            SecretPatternLabel::MultilineAssignment->value => \sprintf('/(["\']?%s(?:[_-][a-z0-9]+){0,8}["\']?\s*(?:=>|[:=]))[ \t]*\r?\n[ \t]*(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2/mi', $inlineCredentialKey),
            SecretPatternLabel::BlockScalar->value => \sprintf('/^([ \t]*+)(-[ \t]++)?(["\']?%s(?:[_-][a-z0-9]+){0,8}["\']?[ \t]*:[ \t]*[|>][+-]?[0-9]?[+-]?[ \t]*(?:#[^\n]*)?)\r?\n((?:\1(?(2)[ \t]{3,}|[ \t]+)[^\n]*(?:\n|\z)|[ \t]*\r?\n)++)/mi', $inlineCredentialKey),
            SecretPatternLabel::CallArgument->value => \sprintf('/(?|((?:->|::)(?:(?:set|with)[A-Za-z0-9_]{0,24}?)?%1$s[ \t]*\([ \t]*)(["\'])%2$s\2|(\([ \t]*["\'][\w.$:\-]{0,64}%3$s[\w.$:\-]{0,64}["\'][ \t]*,[ \t]*)(["\'])%2$s\2|(new[ \t]+\\\\?PDO[ \t]*\([^,\n]{1,200},[^,\n]{1,100},[ \t]*)(["\'])%2$s\2|((?:\$|->)[A-Za-z_]*key[ \t]*=[ \t]*\\\\?(?:hex2bin|sodium_hex2bin|base64_decode|sodium_base642bin)[ \t]*+\([ \t]*+)(["\'])((?:\\\\.|(?!\2)[^\n]){16,}+)\2|(\bpassword_(?:hash|verify)[ \t]*+\([ \t]*+)(["\'])%2$s\2)/i', $callCredentialName, self::QUOTED_BODY_OF_GROUP_TWO, $inlineCredentialKey),
            SecretPatternLabel::XmlParameter->value => \sprintf('~(<(?:parameter|argument)\b[^>]{0,256}?\bkey=(["\'])[^"\'<>]{0,256}?%s[^"\'<>]{0,256}?\2[^>]{0,256}>)(?!\*\*\*REDACTED:)([^<\n]{4,}+)(?=</(?:parameter|argument)>)~i', $inlineCredentialKey),
            SecretPatternLabel::BearerToken->value => '/\bBearer\s+[A-Za-z0-9\-_.]{20,4096}\b/i',
            SecretPatternLabel::BasicAuthorization->value => '~\b((?:proxy-)?authorization\b["\']?\s*(?::|=>|=)\s*["\']?basic\s+)[A-Za-z0-9+/=_\-]{8,4096}~i',
            SecretPatternLabel::OpenAiApiKey->value => '/\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}+/',
            SecretPatternLabel::SlackWebhookUrl->value => '~\bhttps://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+\b~',
            SecretPatternLabel::DiscordWebhookUrl->value => '~\bhttps://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[A-Za-z0-9_\-]+~',
            SecretPatternLabel::GitlabToken->value => '/\bgl(?:pat|ptt|rt|dt|ft|oas|soat|cbt|imt|agent)-[A-Za-z0-9_\-]{20,}/',
            SecretPatternLabel::HuggingFaceToken->value => '/\bhf_[A-Za-z0-9]{30,}\b/',
            SecretPatternLabel::NpmToken->value => '/\bnpm_[A-Za-z0-9]{36}\b/',
            SecretPatternLabel::SendgridApiKey->value => '/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/',
            SecretPatternLabel::PypiToken->value => '/\bpypi-Ag[A-Za-z0-9_\-]{50,}/',
        ];
    }

    private function inlineCredentialKey(): string
    {
        return \sprintf('(?:%s|(?<![a-z])pass(?![_-])|(?<![\w?&-])token(?![\w-]))', self::CREDENTIAL_WORDS);
    }

    private function truncatedPrivateKeyPattern(): string
    {
        return \sprintf('/-----BEGIN %s-----[ \t\r\n]*+(?:[ \t]*[A-Za-z0-9+\/=]{16,}[ \t]*(?:\r?\n|\z))++/', self::PRIVATE_KEY_LABEL);
    }

    /**
     * An environment variable named as a credential: `DB_PASSWORD`,
     * `STRIPE_SECRET_KEY`, `PGPASSWORD`, `MAILER_DSN`.
     */
    private function envCredentialName(): string
    {
        return \sprintf('(?!%s)(?:[A-Z][A-Z0-9]*_){0,8}(?:(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|KEY|DSN)(?:_[A-Z0-9]+){0,8}|%s(?:_[A-Z0-9]+){0,8}|PASS|PW)', self::CREDENTIAL_FREE_DSN_ASSIGNMENT, self::GLUED_ENV_CREDENTIAL_KEY);
    }

    #[Override]
    public function scrub(string $content): string
    {
        foreach ($this->patterns as $label => $pattern) {
            $result = match (SecretPatternLabel::tryFrom($label)) {
                SecretPatternLabel::EnvAssignment => preg_replace_callback($pattern, $this->redactEnvAssignment(...), $content),
                SecretPatternLabel::InlineAssignment => preg_replace_callback($pattern, $this->redactInlineAssignment(...), $content),
                SecretPatternLabel::MultilineAssignment => preg_replace_callback($pattern, $this->redactMultilineAssignment(...), $content),
                SecretPatternLabel::BlockScalar => preg_replace_callback($pattern, $this->redactBlockScalar(...), $content),
                SecretPatternLabel::CallArgument => preg_replace_callback($pattern, $this->redactCallArgument(...), $content),
                SecretPatternLabel::XmlParameter => preg_replace_callback($pattern, $this->redactXmlParameter(...), $content),
                SecretPatternLabel::PemPrivateKey => $this->redactPrivateKeys($pattern, $content),
                SecretPatternLabel::BearerToken => preg_replace_callback($pattern, $this->redactBearerToken(...), $content),
                default => preg_replace($pattern, $this->replacementFor($label), $content),
            };

            if (null === $result) {
                return $this->withheldContent($label, $content);
            }

            $content = $result;
        }

        $quoted = preg_replace(self::YAML_ENTRY_ENDING_IN_CLOSERS, '$1"$2"', $content) ?? $content;

        return preg_replace(self::UNQUOTED_YAML_PLACEHOLDER, '$1"$2"', $quoted) ?? $quoted;
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
     * A shell or dotenv assignment is rewritten to `NAME=***REDACTED***`. A PHP
     * constant declaration is no such assignment: it keeps its spacing, its
     * quotes and its terminator, and a value that is no string literal is code.
     *
     * @param array<int|string, string> $match
     */
    private function redactEnvAssignment(array $match): string
    {
        $isConstantDeclaration = '' !== ($match[2] ?? '');
        if (!$isConstantDeclaration) {
            return \sprintf('%s=%s', $match[1], SecretPatternLabel::EnvAssignment->placeholder());
        }

        $quote = $match[4] ?? '';
        if ('' === $quote) {
            return $match[0];
        }

        return \sprintf('%s%s%s%s%s', $match[1], $match[3], $quote, SecretPatternLabel::EnvAssignment->placeholder(), $quote);
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactInlineAssignment(array $match): string
    {
        $quote = $match[2] ?? '';
        $value = ($match[3] ?? '').($match[4] ?? '');
        $secret = '' === $quote ? rtrim($value, self::STATEMENT_CLOSERS) : $value;

        if ($this->isKeptReadable($secret, $value, '' !== $quote)) {
            return $match[0];
        }

        return \sprintf('%s%s***REDACTED:%s***%s%s', $match[1], $quote, SecretPatternLabel::InlineAssignment->value, $quote, substr($value, \strlen($secret)));
    }

    private function isKeptReadable(string $secret, string $value, bool $quoted): bool
    {
        return self::MINIMUM_SECRET_LENGTH > \strlen($secret)
            || $this->isRedactionPlaceholder($secret)
            || $this->isConfigPlaceholder($value)
            || $this->isCode($value, $quoted)
            || $this->isNeutralLiteral($secret, \strlen($secret) < \strlen($value));
    }

    /**
     * `null`, `true` and `false` carry no secret, nor does a number that a
     * statement or an argument list ends right after; a bare number in YAML or
     * a dotenv file may still be a password.
     */
    private function isNeutralLiteral(string $secret, bool $terminated): bool
    {
        return 1 === preg_match('/\A(?:null|true|false)\z/i', $secret)
            || ($terminated && 1 === preg_match('/\A[+-]?\d+(?:\.\d+)?\z/', $secret));
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

        return \sprintf("%s\n%s***REDACTED:%s***%s", $match[1], $quote, SecretPatternLabel::MultilineAssignment->value, $quote);
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactBlockScalar(array $match): string
    {
        $lines = $match[4];
        if (1 !== preg_match('/([ \t]+)\S/', $lines, $firstLine)) {
            return $match[0];
        }

        return \sprintf("%s%s%s\n%s%s%s", $match[1], $match[2], $match[3], $firstLine[1], SecretPatternLabel::BlockScalar->placeholder(), str_repeat("\n", substr_count($lines, "\n")));
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactCallArgument(array $match): string
    {
        $quote = $match[2];
        $value = $match[3];

        if ($this->isRedactionPlaceholder($value) || $this->isConfigPlaceholder($value)) {
            return $match[0];
        }

        return \sprintf('%s%s%s%s', $match[1], $quote, SecretPatternLabel::CallArgument->placeholder(), $quote);
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactXmlParameter(array $match): string
    {
        if ($this->isConfigPlaceholder($match[3] ?? '')) {
            return $match[0];
        }

        return \sprintf('%s%s', $match[1], SecretPatternLabel::XmlParameter->placeholder());
    }

    private function redactPrivateKeys(string $pattern, string $content): ?string
    {
        $withoutWholeKeys = preg_replace_callback($pattern, $this->redactPreservingLineCount(...), $content);

        return null === $withoutWholeKeys ? null : preg_replace_callback($this->truncatedPrivateKeyPattern(), $this->redactPreservingLineCount(...), $withoutWholeKeys);
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

    /**
     * @param array<int|string, string> $match
     */
    private function redactBearerToken(array $match): string
    {
        return $this->placeholderPreservingLineCount(SecretPatternLabel::BearerToken, $match[0]);
    }

    private function placeholderPreservingLineCount(SecretPatternLabel $secretPatternLabel, string $replaced): string
    {
        return \sprintf('%s%s', $secretPatternLabel->placeholder(), str_repeat("\n", substr_count($replaced, "\n")));
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
            || 1 === preg_match('/\A\$(?:\{[A-Z_][A-Z0-9_]*\}|[A-Z_][A-Z0-9_]*)\z/', $value);
    }

    private function isRedactionPlaceholder(string $value): bool
    {
        return 1 === preg_match('/\A\*\*\*REDACTED:[a-z0-9_]+\*\*\*\z/', $value);
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
