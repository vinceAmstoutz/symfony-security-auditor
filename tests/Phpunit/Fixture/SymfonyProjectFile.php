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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyProjectFileTypeClassifier;

/**
 * Builds a {@see ProjectFile} the way the Symfony profile would, so a test that
 * cares about a file's behaviour rather than its type does not have to name the
 * type. Tests asserting the classification itself use the classifier directly.
 */
final readonly class SymfonyProjectFile
{
    /**
     * @throws InvalidProjectFileException
     */
    public static function create(string $relativePath, string $absolutePath, string $content): ProjectFile
    {
        return ProjectFile::of(
            relativePath: $relativePath,
            absolutePath: $absolutePath,
            content: $content,
            projectFileType: (new SymfonyProjectFileTypeClassifier())->classify($relativePath, $content),
        );
    }
}
