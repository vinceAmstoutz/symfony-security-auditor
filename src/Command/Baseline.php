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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;

/**
 * Reads and writes the JSON baseline file of accepted-finding fingerprints.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class Baseline implements BaselineInterface
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public function load(string $path): array
    {
        if (!$this->filesystem->exists($path)) {
            return [];
        }

        try {
            $decoded = json_decode($this->filesystem->readFile($path), true, 512, \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedBaselineFileException::fromJsonException($path, $jsonException);
        }

        if (!\is_array($decoded)) {
            throw MalformedBaselineFileException::notAJsonArrayOfStrings($path);
        }

        $fingerprints = [];
        foreach ($decoded as $entry) {
            if (!\is_string($entry)) {
                throw MalformedBaselineFileException::notAJsonArrayOfStrings($path);
            }

            $fingerprints[] = $entry;
        }

        return $fingerprints;
    }

    public function save(string $path, array $fingerprints): void
    {
        $this->filesystem->dumpFile(
            $path,
            json_encode($fingerprints, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR).\PHP_EOL,
        );
    }
}
