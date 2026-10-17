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
 * as another kind of value is not stated, and never stands in for one the
 * other call states: a call the recording tool refused for lacking a field is
 * repeated only by a call that names its file and either its title or the
 * type and line both calls state, so another finding of its file is never
 * taken for it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FindingSignature
{
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
        return $this->namesTheFileOf($recorded)
            && ($this->namesTheLocationOf($recorded) || $this->sharesItsTitleWith($recorded));
    }

    private function namesTheFileOf(self $recorded): bool
    {
        return null !== $this->filePath && $this->filePath === $recorded->filePath;
    }

    private function namesTheLocationOf(self $recorded): bool
    {
        return null !== $this->type && $this->type === $recorded->type
            && null !== $this->lineStart && $this->lineStart === $recorded->lineStart;
    }

    private function sharesItsTitleWith(self $recorded): bool
    {
        return null !== $this->title && $this->title === $recorded->title
            && !$this->contradict($this->type, $recorded->type)
            && !$this->contradict($this->lineStart, $recorded->lineStart);
    }

    private function contradict(int|string|null $stated, int|string|null $restated): bool
    {
        return null !== $stated && null !== $restated && $stated !== $restated;
    }
}
