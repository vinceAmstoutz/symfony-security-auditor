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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use function Symfony\Component\String\b;

/**
 * Names a credential in output without disclosing it: a masked preview that
 * matches what a provider console shows next to the key, and a truncated
 * SHA-256 fingerprint that identifies it exactly and reveals nothing at all.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CredentialIdentity
{
    public const string REDACTED_PREVIEW = '…';

    private const string FINGERPRINT_PREFIX = 'SHA256:';

    private const int FINGERPRINT_CHARACTERS = 16;

    private const int LEADING_CHARACTERS = 6;

    private const int TRAILING_CHARACTERS = 4;

    /**
     * Ten characters are revealed, so anything shorter than this would expose
     * more of the credential than it hides.
     */
    private const int MINIMUM_PREVIEWABLE_LENGTH = 24;

    private const string PREVIEWABLE_PATTERN = '/^[\x21-\x7e]+$/';

    private function __construct(
        public string $maskedPreview,
        public string $fingerprint,
    ) {}

    public static function of(string $credential): self
    {
        return new self(self::maskedPreviewOf($credential), self::fingerprintOf($credential));
    }

    private static function maskedPreviewOf(string $credential): string
    {
        if (!self::isPreviewable($credential)) {
            return self::REDACTED_PREVIEW;
        }

        $bytes = b($credential);

        return \sprintf(
            '%s%s%s',
            $bytes->slice(0, self::LEADING_CHARACTERS)->toString(),
            self::REDACTED_PREVIEW,
            $bytes->slice(-self::TRAILING_CHARACTERS)->toString(),
        );
    }

    /**
     * A credential carrying anything outside printable ASCII is a paste
     * accident rather than a provider key, and slicing its bytes would emit
     * a half-codepoint into the console.
     */
    private static function isPreviewable(string $credential): bool
    {
        return b($credential)->length() >= self::MINIMUM_PREVIEWABLE_LENGTH
            && 1 === preg_match(self::PREVIEWABLE_PATTERN, $credential);
    }

    private static function fingerprintOf(string $credential): string
    {
        return self::FINGERPRINT_PREFIX.b(hash('sha256', $credential))->slice(0, self::FINGERPRINT_CHARACTERS)->toString();
    }
}
