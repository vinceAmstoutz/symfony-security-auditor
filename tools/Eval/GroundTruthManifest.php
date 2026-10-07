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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval;

use JsonException;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\Exception\InvalidGroundTruthManifestException;

/**
 * Loads the seeded ground-truth vulnerabilities for an evaluation fixture from
 * a JSON manifest shaped `{"findings": [{"file": "...", "type": "..."}, ...]}`.
 */
final readonly class GroundTruthManifest
{
    /**
     * @param list<ExpectedFinding> $findings
     */
    public function __construct(
        public array $findings,
    ) {}

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw InvalidGroundTruthManifestException::forUnreadablePath($path);
        }

        $contents = file_get_contents($path);
        if (false === $contents) {
            throw InvalidGroundTruthManifestException::forUnreadablePath($path);
        }

        try {
            $decoded = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw InvalidGroundTruthManifestException::fromJsonException($path, $jsonException);
        }

        $findings = \is_array($decoded) ? ($decoded['findings'] ?? null) : null;
        if (!\is_array($findings)) {
            throw InvalidGroundTruthManifestException::forMissingFindingsArray($path);
        }

        return new self(self::parseFindings($findings, $path));
    }

    /**
     * @param array<array-key, mixed> $findings
     *
     * @return list<ExpectedFinding>
     *
     * @throws InvalidGroundTruthManifestException
     */
    private static function parseFindings(array $findings, string $path): array
    {
        $parsed = [];
        foreach (array_values($findings) as $index => $finding) {
            $parsed[] = self::parseFinding($finding, $path, $index);
        }

        return $parsed;
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    private static function parseFinding(mixed $finding, string $path, int $index): ExpectedFinding
    {
        $file = self::nonEmptyString($finding, 'file');
        $type = self::nonEmptyString($finding, 'type');
        if (null === $file || null === $type) {
            throw InvalidGroundTruthManifestException::forInvalidFinding($path, $index);
        }

        return new ExpectedFinding($file, $type);
    }

    private static function nonEmptyString(mixed $finding, string $key): ?string
    {
        $value = \is_array($finding) ? ($finding[$key] ?? null) : null;

        return \is_string($value) && '' !== $value ? $value : null;
    }
}
