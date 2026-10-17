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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * What became of the config file the audited project ships when the audit does
 * not run from that project's own folder: layered over the other files, or
 * skipped as a whole, with the reason, because the run did not ask for it and
 * must not fail on it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditedProjectConfig
{
    /**
     * @param array<array-key, mixed> $config      what the file sets, empty when it was skipped
     * @param ?float                  $httpTimeout the timeout the file raises the user's to, null when it sets none
     */
    private function __construct(
        public string $file,
        public array $config,
        public ?float $httpTimeout,
        public ?string $skipReason,
    ) {}

    /**
     * @param array<array-key, mixed> $config
     */
    public static function layered(string $file, array $config, ?float $httpTimeout): self
    {
        return new self($file, $config, $httpTimeout, null);
    }

    public static function skipped(string $file, string $reason): self
    {
        return new self($file, [], null, $reason);
    }

    public function wasSkipped(): bool
    {
        return null !== $this->skipReason;
    }

    /**
     * The baseline the file names, a relative one anchored to the project, or
     * null when it names none.
     */
    public function baseline(): ?string
    {
        $baseline = $this->audit()['baseline'] ?? null;

        return \is_string($baseline) ? $baseline : null;
    }

    /**
     * What the file sets, spelled as the container reads it back: the anchored
     * baseline carries the project's folder, whose `%` signs the file itself
     * could never hold as text, so they are escaped.
     *
     * @return array<array-key, mixed>
     */
    public function configForContainer(): array
    {
        $baseline = $this->baseline();
        if (null === $baseline) {
            return $this->config;
        }

        $audit = $this->audit();
        $audit['baseline'] = ContainerParameterSyntax::escape($baseline);
        $config = $this->config;
        $config['audit'] = $audit;

        return $config;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function audit(): array
    {
        $audit = $this->config['audit'] ?? null;

        return \is_array($audit) ? $audit : [];
    }
}
