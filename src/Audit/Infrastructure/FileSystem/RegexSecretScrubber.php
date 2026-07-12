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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SecretPatternLabel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;

/**
 * Replaces credential-shaped strings in file content with redacted placeholders.
 *
 * The pattern set covers common high-signal leaks: cloud provider keys, version-control
 * tokens, payment processor keys, generic credential assignments, JWT-shaped tokens,
 * PEM-encoded private keys, env-style token assignments, and connection-string URIs with
 * embedded credentials (e.g. `postgres://user:pass@host`). Each match is replaced
 * with `***REDACTED:<label>***` so downstream prompt builders can still emit a coherent
 * file context without exposing the secret to the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RegexSecretScrubber implements SecretScrubberInterface
{
    /**
     * @var array<string, string> map of pattern label => PCRE pattern. Labels are stable
     *                            and appear in the redaction placeholder.
     */
    // Possessive `*+`/`{4,}+` below: `\\.` and `(?!\2)[^\n]` both match a bare backslash, so a greedy (backtracking) quantifier here lets an unterminated backslash-heavy value elsewhere in the file exhaust pcre.backtrack_limit and silently skip redaction file-wide.
    // `(?!\2)[^\n]` (rather than excluding both quote characters) so a value quoted with one type can contain an unescaped instance of the *other* type — e.g. "don't" inside double quotes — without the closing-quote backreference matching that unrelated character and truncating the redaction mid-value.
    private const array DEFAULT_PATTERNS = [
        SecretPatternLabel::AwsAccessKey->value => '/\bAKIA[0-9A-Z]{16}\b/',
        SecretPatternLabel::GithubToken->value => '/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_\w{22,255})\b/',
        SecretPatternLabel::StripeKey->value => '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/',
        SecretPatternLabel::SlackToken->value => '/\bxox[abprs]-[A-Za-z0-9-]{10,72}\b/',
        SecretPatternLabel::GoogleApiKey->value => '/\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])/',
        SecretPatternLabel::Jwt->value => '/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/',
        SecretPatternLabel::PemPrivateKey->value => '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/',
        SecretPatternLabel::ConnectionUri->value => '~\b([a-z][a-z0-9+.\-]*://)[^:@/\s]*:[^/\s]+@~i',
        SecretPatternLabel::EnvAssignment->value => '/((?:^|\s)(?:[A-Z][A-Z0-9]*_)*(?:TOKEN|SECRET|PASSWORD|PASSWD|KEY|DSN)(?:_[A-Z0-9]+)*)\s*=[ \t]*(?!\s*\n)(?:(["\'])(?:\\\\.|(?!\2)[^\n])*+\2|\S+)/m',
        SecretPatternLabel::InlineAssignment->value => '/(["\']?(?:password|passwd|pwd|secret|credentials|api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["\']?\s*(?:=>|[:=])[ \t]*)(?!\*\*\*REDACTED:)(?:(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2|([^"\'\s]\S{3,}(?:[ \t]+[A-Za-z0-9]+)*))/i',
        SecretPatternLabel::MultilineAssignment->value => '/(["\']?(?:password|passwd|pwd|secret|credentials|api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["\']?\s*(?:=>|[:=]))[ \t]*\r?\n[ \t]*(["\'])((?:\\\\.|(?!\2)[^\n]){4,}+)\2/mi',
    ];

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
    public function __construct(array $additionalPatterns = [])
    {
        $patterns = self::DEFAULT_PATTERNS;
        foreach ($additionalPatterns as $index => $pattern) {
            $error = $this->validatePattern($pattern);
            if (null !== $error) {
                throw SecretScrubberConfigurationException::forInvalidPattern($pattern, $error);
            }

            $patterns[\sprintf('custom_%s', $index)] = $pattern;
        }

        $this->patterns = $patterns;
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
                continue;
            }

            $content = $result;
        }

        return $content;
    }

    private function replacementFor(string $label): string
    {
        return match (SecretPatternLabel::tryFrom($label)) {
            SecretPatternLabel::EnvAssignment => \sprintf('$1=***REDACTED:%s***', $label),
            SecretPatternLabel::ConnectionUri => \sprintf('$1***REDACTED:%s***@', $label),
            default => \sprintf('***REDACTED:%s***', $label),
        };
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactInlineAssignment(array $match): string
    {
        $quote = $match[2] ?? '';
        $value = ($match[3] ?? '').($match[4] ?? '');

        if ($this->isConfigPlaceholder($value)) {
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

        if ($this->isConfigPlaceholder($value)) {
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
        return \sprintf('***REDACTED:%s***%s', SecretPatternLabel::PemPrivateKey->value, str_repeat("\n", substr_count($match[0], "\n")));
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
