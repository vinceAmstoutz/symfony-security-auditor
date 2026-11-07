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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ScrubbedSecretFindings
{
    private const string PLACEHOLDER = '/\*\*\*REDACTED:([a-z0-9_]++)\*\*\*/';

    private const float CONFIDENCE = 0.95;

    /**
     * @return list<Vulnerability>
     */
    public static function in(ProjectFile $projectFile): array
    {
        $findings = [];
        foreach (explode("\n", $projectFile->content()) as $index => $line) {
            $label = self::firstLabelOf($line);
            if (null !== $label) {
                $findings[] = self::finding($projectFile, $index + 1, $line, $label);
            }
        }

        return $findings;
    }

    private static function firstLabelOf(string $line): ?string
    {
        if (1 !== preg_match(self::PLACEHOLDER, $line, $matches)) {
            return null;
        }

        return SecretPatternLabel::Unscannable->value === $matches[1] ? null : $matches[1];
    }

    private static function finding(ProjectFile $projectFile, int $lineNumber, string $line, string $label): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::HARDCODED_SECRET, VulnerabilitySeverity::HIGH, 'Hardcoded secret committed in source', self::CONFIDENCE),
            new CodeLocation($projectFile->relativePath(), $lineNumber, $lineNumber),
            new VulnerabilityNarrative(
                \sprintf('A credential of kind "%s" is committed in this file; the secret scrubber redacted it before analysis.', $label),
                'Anyone with read access to the repository, its history or a build artifact can reuse the credential.',
                \sprintf('The secret scrubber matched the "%s" pattern on this line.', $label),
                'Revoke and rotate the credential, then load it from a secrets vault or an untracked environment file.',
            ),
            trim($line),
        );
    }
}
