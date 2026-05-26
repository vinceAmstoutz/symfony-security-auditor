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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;

/**
 * Replaces credential-shaped strings in file content with redacted placeholders.
 *
 * The pattern set covers common high-signal leaks: cloud provider keys, version-control
 * tokens, payment processor keys, generic credential assignments, JWT-shaped tokens,
 * PEM-encoded private keys, and env-style token assignments. Each match is replaced
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
    private const array DEFAULT_PATTERNS = [
        'aws_access_key' => '/\bAKIA[0-9A-Z]{16}\b/',
        'github_token' => '/\bgh[pousr]_[A-Za-z0-9]{36,255}\b/',
        'stripe_key' => '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/',
        'slack_token' => '/\bxox[abprs]-[A-Za-z0-9-]{10,72}\b/',
        'google_api_key' => '/\bAIza[0-9A-Za-z_\-]{35}\b/',
        'jwt' => '/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/',
        'pem_private_key' => '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/',
        'env_assignment' => '/((?:^|\s)(?:[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|PASSWORD|PASSWD|KEY|API_KEY|DSN)|PASSWORD|SECRET|API_KEY))\s*=\s*(?!\s*\n)([^\s#]+)/m',
        'inline_assignment' => '/(["\']?(?:password|secret|api[_-]?key|access[_-]?token|client[_-]?secret)["\']?\s*(?:=>|[:=])\s*["\'])([^"\'\n]{4,})(["\'])/i',
    ];

    /**
     * @var array<string, string>
     */
    private array $patterns;

    /**
     * @param list<string> $additionalPatterns extra PCRE patterns merged with the defaults.
     *                                         Each pattern is given a synthetic label
     *                                         `custom_<index>` for redaction reporting.
     */
    public function __construct(array $additionalPatterns = [])
    {
        $patterns = self::DEFAULT_PATTERNS;
        foreach ($additionalPatterns as $index => $pattern) {
            $error = $this->validatePattern($pattern);
            if (null !== $error) {
                throw SecretScrubberConfigurationException::forInvalidPattern($pattern, $error);
            }

            $patterns['custom_'.$index] = $pattern;
        }

        $this->patterns = $patterns;
    }

    public function scrub(string $content): string
    {
        foreach ($this->patterns as $label => $pattern) {
            $result = 'inline_assignment' === $label
                ? @preg_replace_callback($pattern, $this->redactInlineAssignment(...), $content)
                : @preg_replace($pattern, $this->replacementFor($label), $content);

            if (null === $result) {
                continue;
            }

            $content = $result;
        }

        return $content;
    }

    private function replacementFor(string $label): string
    {
        return match ($label) {
            'env_assignment' => '$1=***REDACTED:'.$label.'***',
            default => '***REDACTED:'.$label.'***',
        };
    }

    /**
     * @param array<int|string, string> $match
     */
    private function redactInlineAssignment(array $match): string
    {
        if ($this->isConfigPlaceholder($match[2])) {
            return $match[0];
        }

        return $match[1].'***REDACTED:inline_assignment***'.$match[3];
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

        $result = @preg_match($pattern, '');
        if (false === $result) {
            return preg_last_error_msg();
        }

        return null;
    }
}
