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

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
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
        private JsonEncoder $jsonEncoder = new JsonEncoder(),
    ) {}

    public function load(string $path): array
    {
        if (!$this->filesystem->exists($path)) {
            return [];
        }

        try {
            $decoded = $this->jsonEncoder->decode(
                $this->filesystem->readFile($path),
                JsonEncoder::FORMAT,
            );
        } catch (NotEncodableValueException $notEncodableValueException) {
            throw MalformedBaselineFileException::fromDecodingFailure($path, $notEncodableValueException);
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
            $this->jsonEncoder->encode(
                $fingerprints,
                JsonEncoder::FORMAT,
                [JsonEncode::OPTIONS => \JSON_PRETTY_PRINT],
            ).\PHP_EOL,
        );
    }
}
