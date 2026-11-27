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

/**
 * What an audit knows of the audited project as a whole: the packages its
 * lockfile installs and the architecture its files are laid out in.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProjectProfile
{
    private const string SYMFONY_MINIMUM = 'symfony>=';

    private const string SYMFONY_KERNEL = 'symfony/http-kernel';

    private const string UNNAMED_RELEASE = '';

    /**
     * @param array<string, string>|null $installedPackages  package name => locked version, `null` when no lockfile was read
     * @param list<ArchitectureStyle>    $architectureStyles
     * @param list<string>               $boundedContexts
     */
    private function __construct(
        private ?array $installedPackages,
        private array $architectureStyles,
        private array $boundedContexts,
    ) {}

    public static function unknown(): self
    {
        return new self(null, [], []);
    }

    /**
     * A lockfile that installs no `symfony/http-kernel` is not the application's, so it reads as no lockfile.
     *
     * @param array<string, string>|null $installedPackages  package name => locked version, `null` when no lockfile was read
     * @param list<ArchitectureStyle>    $architectureStyles
     * @param list<string>               $boundedContexts    the modules the project splits its domain into
     */
    public static function of(?array $installedPackages, array $architectureStyles, array $boundedContexts = []): self
    {
        return new self(
            self::installsAKernel($installedPackages) ? $installedPackages : null,
            $architectureStyles,
            $boundedContexts,
        );
    }

    /**
     * Tells a Symfony application's lockfile, which always installs `symfony/http-kernel`, from any other.
     *
     * @param array<string, string>|null $installedPackages
     *
     * @phpstan-assert-if-true array<string, string> $installedPackages
     */
    public static function installsAKernel(?array $installedPackages): bool
    {
        return null !== $installedPackages && \array_key_exists(self::SYMFONY_KERNEL, $installedPackages);
    }

    /**
     * @return list<ArchitectureStyle>
     */
    public function architectureStyles(): array
    {
        return $this->architectureStyles;
    }

    /**
     * @return list<string>
     */
    public function boundedContexts(): array
    {
        return $this->boundedContexts;
    }

    public function satisfies(string $requirement): bool
    {
        if (null === $this->installedPackages) {
            return true;
        }

        foreach (explode(' ', $requirement) as $term) {
            if (!$this->holds($term, $this->installedPackages)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<string, string> $installedPackages
     */
    private function holds(string $term, array $installedPackages): bool
    {
        foreach (explode('|', $term) as $alternative) {
            if ($this->isMet($alternative, $installedPackages)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, string> $installedPackages
     */
    private function isMet(string $alternative, array $installedPackages): bool
    {
        if (str_starts_with($alternative, self::SYMFONY_MINIMUM)) {
            $lockedRelease = $this->releaseOf($installedPackages[self::SYMFONY_KERNEL]);

            return self::UNNAMED_RELEASE === $lockedRelease || version_compare($lockedRelease, substr($alternative, \strlen(self::SYMFONY_MINIMUM)), '>=');
        }

        return \array_key_exists($alternative, $installedPackages);
    }

    private function releaseOf(string $lockedVersion): string
    {
        preg_match('/^v?(\d+(?:\.\d+)*)/', $lockedVersion, $matches);

        return $matches[1] ?? self::UNNAMED_RELEASE;
    }
}
