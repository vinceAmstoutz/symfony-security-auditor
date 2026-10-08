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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use JsonException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\MalformedAdvisoryPayloadException;

/**
 * The shape `composer audit --format=json` must have for an advisory lookup to
 * use it: a JSON object holding an `advisories` map, plus the optional
 * `ignored-advisories` map composer reports the advisories the audited
 * project filters out under.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AdvisoryPayload
{
    private const string ADVISORIES_KEY = 'advisories';

    private const string IGNORED_ADVISORIES_KEY = 'ignored-advisories';

    /**
     * @param array<array-key, mixed> $advisories
     * @param array<array-key, mixed> $ignoredAdvisories
     */
    private function __construct(
        public array $advisories,
        public array $ignoredAdvisories,
    ) {}

    /**
     * @throws MalformedAdvisoryPayloadException
     */
    public static function fromJson(string $json): self
    {
        try {
            $decoded = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedAdvisoryPayloadException::forInvalidJson($jsonException);
        }

        if (!\is_array($decoded)) {
            throw MalformedAdvisoryPayloadException::forNonArrayPayload($decoded);
        }

        if (!\array_key_exists(self::ADVISORIES_KEY, $decoded) || !\is_array($decoded[self::ADVISORIES_KEY])) {
            throw MalformedAdvisoryPayloadException::forMissingAdvisoriesKey();
        }

        $ignoredAdvisories = $decoded[self::IGNORED_ADVISORIES_KEY] ?? [];

        return new self($decoded[self::ADVISORIES_KEY], \is_array($ignoredAdvisories) ? $ignoredAdvisories : []);
    }
}
