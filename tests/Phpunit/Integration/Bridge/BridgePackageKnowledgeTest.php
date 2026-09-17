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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge\Fixture\RecordingBridgeProcessBuilder;

/**
 * `ComposerBridgeInstaller` derives a bridge package name from the platform key,
 * hyphenating the ones `symfony/ai-bundle` spells differently. A wrong slug
 * fails only at `composer require`, on the user's machine, so the names it would
 * ask for are read back here against the ones the bundle itself names.
 */
final class BridgePackageKnowledgeTest extends TestCase
{
    private const string BUNDLE_SOURCE = __DIR__.'/../../../../vendor/symfony/ai-bundle/src/AiBundle.php';

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_every_platform_asks_for_the_package_the_bundle_names(): void
    {
        $expected = $this->packagesTheBundleNames();

        $asked = [];
        $filesystem = new Filesystem();

        foreach (array_keys($expected) as $platform) {
            $targetDirectory = sys_get_temp_dir().'/ssa-slug-'.bin2hex(random_bytes(6));
            $recorder = new RecordingBridgeProcessBuilder();

            (new ComposerBridgeInstaller(processBuilder: $recorder(...)))->install($platform, $targetDirectory);
            $filesystem->remove($targetDirectory);

            $asked[$platform] = $recorder->package();
        }

        self::assertSame($expected, $asked);
    }

    /**
     * @return array<string, string>
     */
    private function packagesTheBundleNames(): array
    {
        $source = file_get_contents(self::BUNDLE_SOURCE);
        self::assertNotFalse($source);

        preg_match_all('/if \(\x27([a-z]+)\x27 === \$type[^)]*\) \{/', $source, $branches, \PREG_OFFSET_CAPTURE);

        $packages = [];
        $count = \count($branches[0]);

        for ($index = 0; $index < $count; ++$index) {
            $platform = $branches[1][$index][0];
            $start = $branches[0][$index][1];
            $end = $index + 1 < $count ? $branches[0][$index + 1][1] : \strlen($source);

            if (!\array_key_exists($platform, $packages) && 1 === preg_match('/willBeAvailable\(\x27(symfony\/ai-[a-z-]+-platform)\x27/', substr($source, $start, $end - $start), $named)) {
                $packages[$platform] = $named[1];
            }
        }

        self::assertNotSame([], $packages, 'The bundle names a bridge package for at least one platform');
        ksort($packages);

        return $packages;
    }
}
