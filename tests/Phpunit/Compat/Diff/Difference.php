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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff;

/**
 * One way a replay differs from its recording: a value at a path of the
 * observation that changed, appeared or disappeared, or one line of a text
 * output that the replay lost (`-`) or gained (`+`).
 */
final readonly class Difference
{
    public const string ABSENT = '<absent>';

    private function __construct(
        public string $path,
        public ?string $line,
        public mixed $recorded,
        public mixed $replayed,
    ) {}

    public static function ofValue(string $path, mixed $recorded, mixed $replayed): self
    {
        return new self($path, null, $recorded, $replayed);
    }

    public static function ofLine(string $path, string $line): self
    {
        return new self($path, $line, null, null);
    }

    public function describe(): string
    {
        $subject = $this->subject();

        return \sprintf('%s: %s', $this->path, mb_strlen($subject) > 600 ? \sprintf('%s…', mb_substr($subject, 0, 600)) : $subject);
    }

    /**
     * What changed, without the path: the `-line` or `+line` of a text, or
     * `recorded -> replayed` of a value, each value as JSON.
     */
    public function subject(): string
    {
        return $this->line ?? \sprintf('%s -> %s', $this->render($this->recorded), $this->render($this->replayed));
    }

    private function render(mixed $value): string
    {
        return self::ABSENT === $value ? $value : (string) json_encode($value, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION);
    }
}
