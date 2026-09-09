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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Package;

use PHPUnit\Framework\TestCase;

/**
 * The bundle `replace`s the core rather than requiring it, and ships the core's
 * code through a second `autoload.psr-4` root. Composer therefore never reads
 * the replaced package's manifest: the root manifest alone decides what gets
 * installed, and the core manifest only takes effect once the core is published
 * on its own. Either can then declare less than the code it ships imports — as
 * both did, for `symfony/ai-platform`, `symfony/clock`, `nikic/php-parser` and
 * `ext-dom`. These assertions keep the two answerable to each other.
 */
final class PackageManifestTest extends TestCase
{
    private const string ROOT_MANIFEST = __DIR__.'/../../../../composer.json';

    private const string CORE_MANIFEST = __DIR__.'/../../../../packages/core/composer.json';

    private const string CORE_PACKAGE = 'vinceamstoutz/security-auditor-core';

    private const string PLATFORM_COMPONENT = 'symfony/ai-platform';

    private const string FRAMEWORK_INTEGRATION_BUNDLE = 'symfony/ai-bundle';

    public function test_the_root_manifest_replaces_the_core_package(): void
    {
        self::assertArrayHasKey(
            self::CORE_PACKAGE,
            $this->section(self::ROOT_MANIFEST, 'replace'),
            "The root manifest no longer replaces the core, so it no longer ships the core's code and this parity no longer applies.",
        );
    }

    public function test_the_root_manifest_requires_everything_the_core_requires(): void
    {
        $rootRequire = $this->section(self::ROOT_MANIFEST, 'require');

        foreach ($this->section(self::CORE_MANIFEST, 'require') as $package => $constraint) {
            self::assertArrayHasKey(
                $package,
                $rootRequire,
                \sprintf("The root manifest ships the core's code but does not require %s.", $package),
            );
            self::assertSame(
                $constraint,
                $rootRequire[$package],
                \sprintf('%s is constrained differently by the two manifests.', $package),
            );
        }
    }

    public function test_both_manifests_suggest_the_same_provider_bridges(): void
    {
        self::assertSame(
            $this->section(self::ROOT_MANIFEST, 'suggest'),
            $this->section(self::CORE_MANIFEST, 'suggest'),
            'A provider bridge is suggested by only one of the two manifests.',
        );
    }

    public function test_the_core_depends_on_the_platform_component_not_the_framework_integration(): void
    {
        $coreRequire = $this->section(self::CORE_MANIFEST, 'require');

        self::assertArrayHasKey(
            self::PLATFORM_COMPONENT,
            $coreRequire,
            \sprintf('The core reaches its LLM provider through %s and must require it directly.', self::PLATFORM_COMPONENT),
        );
        self::assertArrayNotHasKey(
            self::FRAMEWORK_INTEGRATION_BUNDLE,
            $coreRequire,
            'The core is framework-agnostic, so it must never depend on the framework integration bundle.',
        );
    }

    /**
     * @return array<string, string>
     */
    private function section(string $manifest, string $key): array
    {
        $contents = file_get_contents($manifest);
        self::assertIsString($contents, \sprintf('%s is unreadable.', $manifest));

        $decoded = json_decode($contents, true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertArrayHasKey($key, $decoded, \sprintf('%s declares no "%s" section.', $manifest, $key));
        self::assertIsArray($decoded[$key]);

        $section = [];

        foreach ($decoded[$key] as $package => $constraint) {
            self::assertIsString($package);
            self::assertIsString($constraint);

            $section[$package] = $constraint;
        }

        return $section;
    }
}
