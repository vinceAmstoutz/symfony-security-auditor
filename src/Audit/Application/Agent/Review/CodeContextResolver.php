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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Resolves the scanned content of the file a finding names, ignoring a
 * leading `./`, or an empty string when the file was not scanned.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CodeContextResolver
{
    /**
     * @param list<ProjectFile> $projectFiles
     */
    public static function resolve(string $filePath, array $projectFiles): string
    {
        $relativePath = EchoedFilePath::normalize($filePath);
        foreach ($projectFiles as $projectFile) {
            if ($projectFile->relativePath() === $relativePath) {
                return $projectFile->content();
            }
        }

        return '';
    }
}
