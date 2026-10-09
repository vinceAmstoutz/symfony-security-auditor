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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

/**
 * What a record call says about the finding it names: the file, type and line
 * its id is derived from, and its title. A field the call leaves out or gives
 * as another kind of value is not stated, so a call the recording tool refused
 * for lacking a field can still be told apart from the other findings of its
 * file and matched to the call that records the finding in full.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FindingSignature
{
    private const int FIELDS_NAMING_A_LOCATION = 2;

    private function __construct(
        private ?string $filePath,
        private ?string $type,
        private ?int $lineStart,
        private ?string $title,
    ) {}

    /**
     * @param array<string, mixed> $payload
     */
    public static function of(array $payload): self
    {
        $filePath = $payload['file_path'] ?? null;
        $type = $payload['type'] ?? null;
        $lineStart = $payload['line_start'] ?? null;
        $title = $payload['title'] ?? null;

        return new self(
            \is_string($filePath) ? EchoedFilePath::normalize($filePath) : null,
            \is_string($type) ? strtolower(trim($type)) : null,
            is_numeric($lineStart) ? (int) $lineStart : null,
            \is_string($title) ? $title : null,
        );
    }

    public function isRepeatedBy(self $recorded): bool
    {
        return $this->sharesFileAndTitleWith($recorded) || $this->namesTheLocationOf($recorded);
    }

    private function sharesFileAndTitleWith(self $recorded): bool
    {
        return null !== $this->filePath
            && $this->filePath === $recorded->filePath
            && null !== $this->title
            && $this->title === $recorded->title;
    }

    private function namesTheLocationOf(self $recorded): bool
    {
        $agreeing = 0;

        foreach ([
            [$this->filePath, $recorded->filePath],
            [$this->type, $recorded->type],
            [$this->lineStart, $recorded->lineStart],
        ] as [$stated, $restated]) {
            if (null === $stated || null === $restated) {
                continue;
            }

            if ($stated !== $restated) {
                return false;
            }

            ++$agreeing;
        }

        return $agreeing >= self::FIELDS_NAMING_A_LOCATION;
    }
}
