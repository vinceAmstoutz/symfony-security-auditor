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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use JsonException;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;

/**
 * Reads the findings of a JSON report that carry a suggested fix, in report
 * order. A finding with no fix, or whose fix or file is not text, has none.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SuggestedFixReader
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @return list<SuggestedFix>
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function read(string $path): array
    {
        $suggestedFixes = [];
        foreach ($this->vulnerabilitiesIn($path) as $vulnerability) {
            $suggestedFix = \is_array($vulnerability) ? $this->suggestedFixOf($vulnerability) : null;
            if ($suggestedFix instanceof SuggestedFix) {
                $suggestedFixes[] = $suggestedFix;
            }
        }

        return $suggestedFixes;
    }

    /**
     * @param array<array-key, mixed> $vulnerability
     */
    private function suggestedFixOf(array $vulnerability): ?SuggestedFix
    {
        $patch = $vulnerability['suggested_fix'] ?? null;
        $file = $vulnerability['file'] ?? null;
        $title = $vulnerability['title'] ?? null;

        return \is_string($patch) && \is_string($file) && \is_string($title) ? new SuggestedFix($title, $file, $patch) : null;
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    private function vulnerabilitiesIn(string $path): array
    {
        try {
            $decoded = json_decode($this->filesystem->readFile($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (IOException $ioException) {
            throw ReportFileNotReadableException::forPath($path, $ioException);
        } catch (JsonException $jsonException) {
            throw MalformedReportFileException::fromJsonException($path, $jsonException);
        }

        $vulnerabilities = \is_array($decoded) ? ($decoded['vulnerabilities'] ?? null) : null;
        if (!\is_array($vulnerabilities)) {
            throw MalformedReportFileException::missingVulnerabilitiesArray($path);
        }

        return $vulnerabilities;
    }
}
