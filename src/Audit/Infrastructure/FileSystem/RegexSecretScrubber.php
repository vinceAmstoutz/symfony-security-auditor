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

use Closure;
use Override;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SecretPatternLabel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PathAwareSecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;

/**
 * Replaces credential-shaped strings with `***REDACTED:<label>***`: provider keys and tokens,
 * private keys, the key of a Symfony secrets vault, credential assignments and parameters,
 * connection URIs holding a credential, credentials in a URL query or an `Authorization` header
 * and the literal arguments of a call that takes a credential.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class RegexSecretScrubber implements PathAwareSecretScrubberInterface
{
    /**
     * A credential word glued to a known qualifier (`APIKEY`, `DBPASS`), never
     * `MONKEY` or `COMPASS`.
     */
    private const string GLUED_ENV_CREDENTIAL_KEY = '(?:API|APP|AUTH|ACCESS|SECRET|PRIVATE|CLIENT|MASTER|ACCOUNT|SIGNING|ENCRYPTION|JWT|OAUTH|SESSION|REFRESH|BEARER|PASS|DB|DATABASE|ROOT|ADMIN|USER|MYSQL|POSTGRES|PG|MONGO|REDIS|SMTP|MAIL|FTP|SSH){1,4}(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|PASS)';

    /**
     * A placeholder standing alone as a plain YAML value, which gets quoted:
     * YAML reads a leading `*` as an alias.
     */
    private const string UNQUOTED_YAML_PLACEHOLDER = '/([:\-][ \t]++)(\*\*\*REDACTED:[a-z0-9_]++\*\*\*)(?=[ \t]*+(?:[,})\]#]|\r?$))/m';

    /**
     * The fallbacks after an operand: `?: 'x'`, `?? 'x'`, `. 'x'`, `? $a : 'x'`.
     */
    private const string FALLBACK_TAIL = '((?:[ \t]++(?:\?\?|\?:|[?:.])[ \t]++(?:"(?:[^"\\\\\n]++|\\\\.)*+"|\'(?:[^\'\\\\\n]++|\\\\.)*+\'|[^\s"\';,)\]]++)){1,16}+)';

    private const string FALLBACK_LITERAL = '/((?:\?\?|\?:|[?:.])[ \t]++)(?|(")((?![\/\\\\.])(?=(?:\\\\.|[^"\\\\\n]){4})(?:[^"\\\\\n]++|\\\\.)*+)"|(\')((?![\/\\\\.])(?=(?:\\\\.|[^\'\\\\\n]){4})(?:[^\'\\\\\n]++|\\\\.)*+)\')/';

    private const string STATEMENT_CLOSERS = ';:,\'")]';

    private const string ENDS_IN_ESCAPE = '/(?<!\\\\)(?:\\\\\\\\)*+\\\\\z/';

    private const int MINIMUM_SECRET_LENGTH = 4;

    /**
     * A DSN assignment with no user part and no credential-named parameter
     * (`MAILER_DSN=null://null`), left as written.
     */
    private const string CREDENTIAL_FREE_DSN_ASSIGNMENT = '(?:[A-Z][A-Z0-9]*_){0,8}DSN(?:_[A-Z0-9]+){0,8}\s*=[ \t]*["\']?[a-z][a-z0-9+.\-]{0,31}:\/\/(?![^\s"\'@?;]{0,256}+[?;][^\s"\'@]{0,256}(?i:auth|key|token|secret|pass|pwd|cred))[^@\s"\']{0,256}+(?:["\']|\s|\z)';

    /**
     * A user part holding a password: one followed by a colon, or one alone on a Redis, Valkey or
     * mailer API URL or before a `default` host (`ntfy://TOKEN@default`).
     */
    private const string CONNECTION_URI = '~\b(?|([a-z][a-z0-9+.\-]{0,31}://)[^:@/\s]*:[^/\s]+|((?:rediss?|valkeys?|sendgrid|[a-z0-9.\-]{1,31}\+api)://)(?![%$])[^:@/\s]{4,}+|([a-z][a-z0-9+.\-]{0,31}://)(?![%$])[^:@/\s]{4,}+(?=@default\b))@~i';

    /**
     * The credential of an `Authorization` header of any scheme, when it ends the value as a
     * header does: `new AuthorizationChecker($storage)` is code.
     */
    private const string AUTHORIZATION_HEADER = '/(?:proxy-)?authorization\b["\']?[ \t]*(?::|=>|=)[ \t]*["\']?[A-Za-z][A-Za-z0-9_-]{0,31}[ \t]++\K[A-Za-z0-9+\/=_.~:-]{8,}+(?=["\'\s]|\z)/i';

    /**
     * A credential in a URL query (`?token=…`, `&sig=…`), unless it is a placeholder (`?token=%s`,
     * `?token={token}`).
     */
    private const string QUERY_CREDENTIAL = '/[?&](?:(?:access|auth|api|private|refresh|id|client|secret)_?)?(?:token|key|secret|sig|signature|password|passwd|pwd)=\K(?:[A-Za-z0-9._~+\/=-]|%[0-9A-Fa-f]{2}){8,}+(?![%{$])/i';

    private const string PRIVATE_KEY_LABEL = '(?:(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)';

    /**
     * A quoted fragment joined to a variable or a call: `'" . $pass . "'`.
     */
    private const string CONCATENATED_CODE = '/["\']\s*\.\s*(?:\$[A-Za-z_]|[a-z_]\w*\s*\()|(?:\$[A-Za-z_]\w*|\))\s*\.\s*["\']/';

    /**
     * The first word of an unquoted value, shaped the way only PHP code is: a
     * variable access, a class or global constant, an array or parenthesized
     * expression, or a call (`$request->`, `self::SECRET`, `[$a, $b]`,
     * `uniqid();`). `$2y$13$…`, `summer(2024)` and `P4ss::WORD_1` match none.
     */
    private const string PHP_EXPRESSION = '/^!?(?:\$[A-Za-z_]\w*(?:[;,)\]]*$|->|\?->|::|\[)|(?:self|static|parent)::[A-Z_][A-Z0-9_]*[;,)\]]*$|[A-Z]\w*::[A-Z_][A-Z0-9_]*[;,)\]]+$|\\\\[A-Za-z_][\w\\\\]*(?:::[A-Za-z_]\w*)?[;,)\]]*$|\[(?:["\'$\]]|\.\.\.)|\((?:\$[A-Za-z_]|new$)|\\\\?[a-z_]\w*\([a-z_]\w*\(|(?:\\\\?[a-z_]\w*|(?:self|static|parent|[A-Z]\w*)::[A-Za-z_]\w*)\((?:(?:[\'"$]|[a-z_]\w*\().*[,;()\]]|.*[;,])$)/';

    private const string CREDENTIAL_WORDS = 'password|passwd|pwd|pass[_-]?phrase|secret|credentials|api[_-]?key|api[_-]?token|api[_-]?secret|access[_-]?token|access[_-]?key|auth[_-]?token|auth[_-]?key|auth[_-]?bearer|auth[_-]?basic|client[_-]?secret|private[_-]?key|account[_-]?key|secret[_-]?key|app[_-]?key|app[_-]?secret|master[_-]?key|signing[_-]?key|encryption[_-]?key|session[_-]?secret|jwt[_-]?secret|refresh[_-]?token|bearer[_-]?token|(?:db|database|root|admin|user|mysql|postgres|pg|mongo|redis|smtp|mail|ftp|ssh)[_-]?pass(?:word|wd)?';

    private const string PURE_VALUE_FUNCTIONS = 'hex2bin|bin2hex|base64_decode|base64_encode|sodium_hex2bin|sodium_base642bin|password_hash|md5|sha1|trim|ltrim|rtrim|strtolower|strtoupper|urldecode|rawurldecode|urlencode|rawurlencode';

    /**
     * The decryption key a Symfony secrets vault returns: a 64-byte literal
     * holding `\xHH` escapes, or any literal returned under a
     * `// SYMFONY_DECRYPTION_SECRET=` line.
     */
    private const string SECRETS_VAULT_KEY = '/(?:\bSYMFONY_DECRYPTION_SECRET=[^\n]{0,256}+\n[ \t]*+return[ \t]*+"\K(?:\\\\x[0-9A-Fa-f]{2}|[A-Za-z0-9_.~-])++|\breturn[ \t]*+"\K(?=[^"\n]{0,255}?\\\\x)(?:\\\\x[0-9A-Fa-f]{2}|[A-Za-z0-9_.~-]){64})(?=")/';

    /**
     * The name Symfony gives the decryption key of a secrets vault, `<vault>/<vault>.decrypt.private.php`.
     */
    private const string SECRETS_VAULT_KEY_FILE = '.decrypt.private.php';

    private const string QUOTED_BODY_OF_GROUP_THREE = '((?:\\\\.|(?!\3)[^\n]){4,}+)';

    private const string QUOTED_LITERAL = '"(?:[^"\\\\\n]++|\\\\.)*+"|\'(?:[^\'\\\\\n]++|\\\\.)*+\'';

    /**
     * A literal standing as a whole argument, by position or by name: not one inside a nested
     * call, nor one concatenated with something else.
     */
    private const string ARGUMENT_LITERAL = '/(\A|,)([ \t\r\n]*+(?:[A-Za-z_]\w*+[ \t]*+:(?!:)[ \t\r\n]*+)?)(["\'])((?:\\\\.|(?!\3)[^\n]){4,}+)\3(?=[ \t\r\n]*+(?:,|\z))/';

    /**
     * @var array<string, string>
     */
    private array $patterns;

    /**
     * @param list<mixed>                   $additionalPatterns extra PCRE patterns, each labeled `custom_<index>`;
     *                                                          one that is not text is refused
     * @param ?Closure(string): PhpDataMask $phpDataMaskFactory defaults to PhpDataMask::of
     *
     * @throws SecretScrubberConfigurationException
     */
    public function __construct(
        array $additionalPatterns = [],
        private LoggerInterface $logger = new NullLogger(),
        private OffsetCaptureReplacer $offsetCaptureReplacer = new OffsetCaptureReplacer(),
        private ?Closure $phpDataMaskFactory = null,
    ) {
        $patterns = $this->defaultPatterns();
        foreach ($additionalPatterns as $index => $pattern) {
            if (!\is_string($pattern)) {
                throw SecretScrubberConfigurationException::forPatternThatIsNoText($index, $pattern);
            }

            $error = $this->validatePattern($pattern);
            if (null !== $error) {
                throw SecretScrubberConfigurationException::forInvalidPattern($pattern, $error);
            }

            $patterns[\sprintf('custom_%s', $index)] = $pattern;
        }

        $this->patterns = $patterns;
    }

    /**
     * Quantifiers stay possessive and repetitions bounded, so a crafted file cannot exhaust
     * `pcre.backtrack_limit` or the JIT stack and get itself withheld.
     *
     * @return array<string, string> pattern label => PCRE pattern; the label appears in the placeholder
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
            SecretPatternLabel::SecretsVaultKey->value => self::SECRETS_VAULT_KEY,
            SecretPatternLabel::PemPrivateKey->value => \sprintf('/-----BEGIN %1$s-----(*COMMIT)[\s\S]*?-----END %1$s-----/', self::PRIVATE_KEY_LABEL),
            SecretPatternLabel::ConnectionUri->value => self::CONNECTION_URI,
            SecretPatternLabel::EnvAssignment->value => \sprintf('/((?:^|\s)(const\s+(?:[?\w\\\\|&]+\s+)?|case\s+)?%s)(\s*=[ \t]*)(?!\s*\n)(?:(["\'])(?:\\\\.|(?!\4)[^\r\n])*+(?:\4|(?=\r?$))|\S+)/m', $envCredentialName),
            SecretPatternLabel::InlineAssignment->value => \sprintf('/(["\']?(?:%1$s(?:[_-][a-z0-9]+){0,8}["\']?\]?\s*(?:=>|:(?!:)|=)|env\(%2$s\)["\']?\s*:|define\(\s*["\']%2$s["\']\s*,)[ \t]*(?:\((?:string|int|integer|float|double|bool|boolean|array|object)\)[ \t]*)?+(?:\\\\?(?:%3$s)[ \t]*+\([ \t]*+(?=["\']))?)(?!\*\*\*REDACTED:)(?:(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2|(?|([^"\'\s]\S{3,}(?:(?<![;:)\]\'"])(?:(?<!,)|(?![ \t]*+[\w-]++[ \t]*+:))(?:[ \t]*+[A-Za-z0-9]++)++)?)(?:(?<![;,])%4$s)?+|([^"\'\s]\S{0,2}+)(?<![;,])%4$s))/i', $inlineCredentialKey, $envCredentialName, self::PURE_VALUE_FUNCTIONS, self::FALLBACK_TAIL),
            SecretPatternLabel::MultilineAssignment->value => \sprintf('/(["\']?%s(?:[_-][a-z0-9]+){0,8}["\']?\s*(?:=>|[:=]))[ \t]*\r?\n[ \t]*(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2/mi', $inlineCredentialKey),
            SecretPatternLabel::BlockScalar->value => \sprintf('/^([ \t]*+)(-[ \t]++)?(["\']?%s(?:[_-][a-z0-9]+){0,8}["\']?[ \t]*:[ \t]*[|>][+-]?[0-9]?[+-]?[ \t]*(?:#[^\n]*)?)\r?\n((?:\1(?(2)[ \t]{3,}|[ \t]+)[^\n]*(?:\n|\z)|[ \t]*\r?\n)++)/mi', $inlineCredentialKey),
            SecretPatternLabel::CallArgument->value => \sprintf('/(?|((?>%4$s[ \t]*\())%5$s|(["\']auth(?:[_-]?basic)?["\'][ \t]*(?:=>|:)[ \t]*\[)%6$s|(\([ \t]*["\'][\w.$:\-]{0,64}%3$s[\w.$:\-]{0,64}["\'][ \t]*,[ \t]*)((["\'])%2$s\3)|(new[ \t]+\\\\?PDO[ \t]*\([^,\n]{1,200},[^,\n]{1,100},[ \t]*)((["\'])%2$s\3)|((?:\$|->)[A-Za-z_]*key[ \t]*=[ \t]*\\\\?(?:hex2bin|sodium_hex2bin|base64_decode|sodium_base642bin)[ \t]*+\([ \t]*+)((["\'])((?:\\\\.|(?!\3)[^\n]){16,}+)\3)|(\bpassword_(?:hash|verify)[ \t]*+\([ \t]*+)((["\'])%2$s\3))/i', $callCredentialName, self::QUOTED_BODY_OF_GROUP_THREE, $inlineCredentialKey, $this->credentialCall($callCredentialName), $this->callArguments(), $this->listItems()),
            SecretPatternLabel::XmlParameter->value => \sprintf('~(<(?:parameter|argument)\b[^>]{0,256}?\bkey=(["\'])[^"\'<>]{0,256}?%s[^"\'<>]{0,256}?\2[^>]{0,256}>)(?!\*\*\*REDACTED:)([^<\n]{4,}+)(?=</(?:parameter|argument)>)~i', $inlineCredentialKey),
            SecretPatternLabel::BearerToken->value => '/\bBearer\s+[A-Za-z0-9\-_.]{20,4096}\b/i',
            SecretPatternLabel::BasicAuthorization->value => '~\b((?:proxy-)?authorization\b["\']?\s*(?::|=>|=)\s*["\']?basic\s+)[A-Za-z0-9+/=_\-]{8,4096}~i',
            SecretPatternLabel::AuthorizationHeader->value => self::AUTHORIZATION_HEADER,
            SecretPatternLabel::QueryCredential->value => self::QUERY_CREDENTIAL,
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

    /**
     * A call taking a credential as a literal argument: a setter named after one
     * (`setPassword()`), a client logging in with one (`ldap_bind()`, `$redis->auth()`) or a class
     * holding one (`new Credentials()`).
     */
    private function credentialCall(string $callCredentialName): string
    {
        return \sprintf('(?:(?:->|::)(?:(?:set|with)[A-Za-z0-9_]{0,24}?(?:%1$s|auth)|%1$s)|redis[A-Za-z0-9_]{0,64}->auth|ldap[A-Za-z0-9_]{0,64}->bind|\b(?:ldap_bind|ftp_login|ssh2_auth_password|imap_open|mysqli_connect|mysqli_real_connect)|\bnew[ \t]+\\\\?(?:[A-Za-z_][A-Za-z0-9_]{0,64}\\\\){0,8}(?:mysqli|[A-Za-z0-9_]{0,64}credentials))', $callCredentialName);
    }

    /**
     * The arguments of a call, up to its closing parenthesis, with calls nested two deep in them.
     */
    private function callArguments(): string
    {
        return \sprintf('((?:[^()"\']++|%1$s|\((?:[^()"\']++|%1$s|\((?:[^()"\']++|%1$s)*+\))*+\))*+)(?=\))', self::QUOTED_LITERAL);
    }

    /**
     * The items of a list, up to its closing bracket, such as a Guzzle `auth` option.
     */
    private function listItems(): string
    {
        return \sprintf('((?:[^\\[\\]()"\']++|%s)*+)(?=\\])', self::QUOTED_LITERAL);
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
        $phpDataMaskMemo = new PhpDataMaskMemo($this->phpDataMaskFactory ?? PhpDataMask::of(...));
        foreach ($this->patterns as $label => $pattern) {
            $result = match (SecretPatternLabel::tryFrom($label)) {
                SecretPatternLabel::EnvAssignment => $this->redactEnvAssignments($pattern, $content, $phpDataMaskMemo),
                SecretPatternLabel::InlineAssignment => $this->redactInlineAssignments($pattern, $content, $phpDataMaskMemo),
                SecretPatternLabel::MultilineAssignment => preg_replace_callback($pattern, $this->redactMultilineAssignment(...), $content),
                SecretPatternLabel::BlockScalar => preg_replace_callback($pattern, $this->redactBlockScalar(...), $content),
                SecretPatternLabel::CallArgument => $this->redactCallArguments($pattern, $content, $phpDataMaskMemo),
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

        return PhpDataMask::opensWithPhpTag($content) ? $content : (preg_replace(self::UNQUOTED_YAML_PLACEHOLDER, '$1"$2"', $content) ?? $content);
    }

    /**
     * Redacts every string literal of a file named like a Symfony secrets vault's decryption key.
     */
    #[Override]
    public function scrubFile(string $relativePath, string $content): string
    {
        $scrubbed = $this->scrub($content);

        return str_ends_with($relativePath, self::SECRETS_VAULT_KEY_FILE) ? $this->redactStringLiterals($scrubbed) : $scrubbed;
    }

    /**
     * Keeps the line count: each body becomes the placeholder and the line breaks it spanned.
     */
    private function redactStringLiterals(string $content): string
    {
        return array_reduce(
            array_reverse(PhpDataMask::of($content)->stringBodies()),
            static fn (string $redacted, array $body): string => substr_replace($redacted, \sprintf('%s%s', SecretPatternLabel::SecretsVaultKey->placeholder(), str_repeat("\n", substr_count($redacted, "\n", $body[0], $body[1]))), $body[0], $body[1]),
            $content,
        );
    }

    /**
     * Withholds the whole content once a pattern cannot be evaluated: part-scanned content could
     * still hold a credential.
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
     * Whether a value assigned to a credential-named key is PHP code (a variable access, a class
     * constant, a call, a quoted fragment joined to a variable or a call), which stays readable
     * for the audit. A literal written in exactly one of those shapes is read as code too.
     */
    private function isCode(string $value, bool $quoted): bool
    {
        return $quoted
            ? 1 === preg_match(self::CONCATENATED_CODE, $value)
            : 1 === preg_match(self::PHP_EXPRESSION, explode(' ', strtr($value, "\t", ' '))[0]);
    }

    private function redactEnvAssignments(string $pattern, string $content, PhpDataMaskMemo $phpDataMaskMemo): ?string
    {
        return $this->offsetCaptureReplacer->replaceSharing($pattern, $content, static fn (): PhpDataMask => $phpDataMaskMemo->of($content), $this->redactEnvAssignment(...));
    }

    /**
     * Rewrites a shell or dotenv assignment to `NAME=***REDACTED***`. A PHP constant declaration
     * keeps its spacing, quotes and terminator. A value that is no string literal stays.
     *
     * @param array<int|string, array{0: string, 1: int}> $match
     */
    private function redactEnvAssignment(array $match, PhpDataMask $phpDataMask): string
    {
        $prefixLength = \strlen($match[1][0]) + \strlen($match[3][0]);
        $valueOffset = $match[3][1] + \strlen($match[3][0]);
        $value = substr($match[0][0], $prefixLength);

        if ('' !== ($match[2][0] ?? '')) {
            return $this->redactConstantDeclaration($match, $phpDataMask, $valueOffset, \strlen($value));
        }

        $redactable = $phpDataMask->textLength($valueOffset, \strlen($value));
        if (0 === $redactable) {
            return $match[0][0];
        }

        return \sprintf('%s=%s%s', $match[1][0], SecretPatternLabel::EnvAssignment->placeholder(), substr($value, $redactable));
    }

    /**
     * @param array<int|string, array{0: string, 1: int}> $match
     */
    private function redactConstantDeclaration(array $match, PhpDataMask $phpDataMask, int $valueOffset, int $valueLength): string
    {
        $quote = $match[4][0] ?? '';
        $lastOffset = $valueOffset + $valueLength - 1;
        if ('' === $quote || !$phpDataMask->isStringLiteral($valueOffset, $lastOffset)) {
            return $match[0][0];
        }

        return \sprintf('%s%s%s%s%s', $match[1][0], $match[3][0], $quote, SecretPatternLabel::EnvAssignment->placeholder(), $quote);
    }

    private function redactInlineAssignments(string $pattern, string $content, PhpDataMaskMemo $phpDataMaskMemo): ?string
    {
        return $this->offsetCaptureReplacer->replaceSharing($pattern, $content, static fn (): PhpDataMask => $phpDataMaskMemo->of($content), $this->redactInlineAssignment(...));
    }

    /**
     * Redacts only text, never code, so the file still parses. A value reaching past the text it
     * starts in is cut where that text ends.
     *
     * @param array<int|string, array{0: string, 1: int}> $match
     */
    private function redactInlineAssignment(array $match, PhpDataMask $phpDataMask): string
    {
        $quote = $match[2][0] ?? '';
        $value = ($match[3][0] ?? '').($match[4][0] ?? '');
        $length = \strlen($value);
        $redactable = '' === $quote ? $phpDataMask->textLength($match[4][1], $length) : $phpDataMask->literalLength($match[2][1], $length);
        $candidate = substr($value, 0, $redactable);
        $secret = '' === $quote ? $this->secretBeforeItsClosers($candidate) : $candidate;
        $tail = $match[5][0] ?? '';
        $redactedTail = '' === $tail ? '' : $this->redactFallbackLiterals($tail, $match[5][1], $phpDataMask);

        if ($this->isKeptReadable($secret, $candidate, '' !== $quote)) {
            return substr($match[0][0], 0, \strlen($match[0][0]) - \strlen($tail)).$redactedTail;
        }

        return \sprintf('%s%s***REDACTED:%s***%s%s%s', $match[1][0], $quote, SecretPatternLabel::InlineAssignment->value, $quote, substr($value, \strlen($secret)), $redactedTail);
    }

    private function redactFallbackLiterals(string $tail, int $tailOffset, PhpDataMask $phpDataMask): string
    {
        return $this->offsetCaptureReplacer->replace(self::FALLBACK_LITERAL, $tail, fn (array $match): string => $this->redactFallbackLiteral($match, $phpDataMask, $tailOffset)) ?? $tail;
    }

    /**
     * @param array<int|string, array{0: string, 1: int}> $match
     */
    private function redactFallbackLiteral(array $match, PhpDataMask $phpDataMask, int $tailOffset): string
    {
        $body = $match[3][0];
        if ($this->isRedactionPlaceholder($body) || $this->isConfigPlaceholder($body) || 0 === $phpDataMask->literalLength($tailOffset + $match[2][1], \strlen($body))) {
            return $match[0][0];
        }

        return \sprintf('%s%s***REDACTED:%s***%s', $match[1][0], $match[2][0], SecretPatternLabel::InlineAssignment->value, $match[2][0]);
    }

    private function secretBeforeItsClosers(string $candidate): string
    {
        $secret = rtrim($candidate, self::STATEMENT_CLOSERS);

        return $secret !== $candidate && $this->endsInEscape($secret) ? substr($candidate, 0, \strlen($secret) + 1) : $secret;
    }

    private function endsInEscape(string $text): bool
    {
        return 1 === preg_match(self::ENDS_IN_ESCAPE, $text);
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
     * `null`, `true`, `false` and a number a statement or an argument list ends right after. A
     * bare number in YAML or a dotenv file may still be a password.
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
     * Redacts each literal standing as a whole argument of a credential call, the user beside the
     * password included, when PHP reads it as a string.
     */
    private function redactCallArguments(string $pattern, string $content, PhpDataMaskMemo $phpDataMaskMemo): ?string
    {
        return $this->offsetCaptureReplacer->replaceSharing($pattern, $content, static fn (): PhpDataMask => $phpDataMaskMemo->of($content), fn (array $match, PhpDataMask $phpDataMask): string => $match[1][0].$this->redactArgumentLiterals($match[2], $phpDataMask));
    }

    /**
     * @param array{0: string, 1: int} $arguments the arguments and their offset in the content
     */
    private function redactArgumentLiterals(array $arguments, PhpDataMask $phpDataMask): string
    {
        return $this->offsetCaptureReplacer->replace(self::ARGUMENT_LITERAL, $arguments[0], fn (array $match): string => $this->redactArgumentLiteral($match, $arguments[1], $phpDataMask)) ?? $arguments[0];
    }

    /**
     * @param array<int|string, array{0: string, 1: int}> $match
     */
    private function redactArgumentLiteral(array $match, int $argumentsOffset, PhpDataMask $phpDataMask): string
    {
        $body = $match[4][0];
        $opening = $argumentsOffset + $match[3][1];

        return $this->isRedactionPlaceholder($body) || $this->isConfigPlaceholder($body) || !$phpDataMask->isStringLiteral($opening, $opening + \strlen($body) + 1)
            ? $match[0][0]
            : \sprintf('%s%s%3$s%4$s%3$s', $match[1][0], $match[2][0], $match[3][0], SecretPatternLabel::CallArgument->placeholder());
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
     * Keeps the file's line count, so the line numbers of findings below the key still hold.
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
     * A Symfony parameter (`%env(FOO)%`, `%kernel.secret%`) or a shell expansion (`$FOO`,
     * `${FOO}`), which stays readable: it holds no secret.
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
