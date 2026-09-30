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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CompoundPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EndpointPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatformBlock;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OptionalApiKeyPlatforms;

/**
 * `BaseUrlPlatforms`, `CompoundPlatforms`, `EndpointPlatforms`, `HandWrittenPlatforms`, `InstanceKeyedPlatforms` and
 * `OptionalApiKeyPlatforms` restate what `symfony/ai-bundle`
 * declares about each platform's connection block. A bundle upgrade that adds a
 * platform, or gives an existing one a `base_url`, would otherwise leave them
 * quietly wrong: `init` would stop asking for a key it now needs, or keep
 * refusing a platform it could write. Reading the bundle's own definitions back
 * turns that into a failing test.
 */
final class PlatformShapeKnowledgeTest extends TestCase
{
    private const string PLATFORM_CONFIG_GLOB = __DIR__.'/../../../../vendor/symfony/ai-bundle/config/platform';

    /**
     * @var list<string>
     */
    private const array ENDPOINTS_DEFAULTED_BY_THE_BRIDGE = ['together'];

    public function test_every_platform_declaring_a_base_url_is_named(): void
    {
        self::assertSame(BaseUrlPlatforms::NAMES, $this->platformsDeclaring('base_url'));
    }

    public function test_azure_and_higgsfield_are_the_only_platforms_both_declaring_a_base_url_and_hand_written(): void
    {
        self::assertSame(
            ['azure', 'higgsfield'],
            array_values(array_intersect(BaseUrlPlatforms::NAMES, array_keys(HandWrittenPlatforms::REQUIREMENTS))),
        );
    }

    public function test_every_platform_declaring_an_endpoint_is_named(): void
    {
        self::assertSame(EndpointPlatforms::NAMES, $this->platformsDeclaring('endpoint'));
    }

    public function test_every_endpoint_platform_leaving_it_without_a_default_is_named(): void
    {
        self::assertSame(
            EndpointPlatforms::WITHOUT_A_DEFAULT,
            array_values(array_diff($this->platformsDeclaringANodeWithoutADefault('endpoint'), self::ENDPOINTS_DEFAULTED_BY_THE_BRIDGE)),
        );
    }

    public function test_every_endpoint_the_bridge_defaults_is_still_left_without_one_by_the_bundle(): void
    {
        self::assertSame([], array_values(array_diff(self::ENDPOINTS_DEFAULTED_BY_THE_BRIDGE, $this->platformsDeclaringANodeWithoutADefault('endpoint'))));
    }

    /**
     * A platform names its connection URL `base_url` or `endpoint`, never both,
     * which is what lets `--base-url` and `--endpoint` stay separate options
     * that each refuse what the other accepts.
     */
    public function test_no_platform_declares_both_an_endpoint_and_a_base_url(): void
    {
        self::assertSame([], array_values(array_intersect(EndpointPlatforms::NAMES, BaseUrlPlatforms::NAMES)));
    }

    /**
     * The `--endpoint` refusal names `EndpointPlatforms::NAMES` verbatim, so a
     * platform that became hand-written or instance-keyed would be advertised
     * as an answer and then refused for a second reason.
     */
    public function test_every_endpoint_platform_is_flat_and_writable(): void
    {
        self::assertSame(
            [],
            array_values(array_intersect(EndpointPlatforms::NAMES, [...array_keys(HandWrittenPlatforms::REQUIREMENTS), ...InstanceKeyedPlatforms::NAMES])),
        );
    }

    public function test_every_writable_platform_leaving_its_api_key_optional_is_named(): void
    {
        self::assertSame(
            OptionalApiKeyPlatforms::NAMES,
            array_values(array_diff($this->platformsDeclaringAnOptionalApiKey(), array_keys(HandWrittenPlatforms::REQUIREMENTS))),
        );
    }

    public function test_every_platform_declared_per_instance_is_named(): void
    {
        self::assertSame(InstanceKeyedPlatforms::NAMES, $this->platformsDeclaring_useAttributeAsKey());
    }

    #[DataProvider('handWrittenPlatformCases')]
    public function test_every_hand_written_platform_has_a_block_to_paste(string $platform): void
    {
        self::assertArrayHasKey($platform, HandWrittenPlatformBlock::CONNECTIONS);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function handWrittenPlatformCases(): iterable
    {
        foreach (array_keys(HandWrittenPlatforms::REQUIREMENTS) as $platform) {
            yield $platform => [$platform];
        }
    }

    public function test_every_setting_of_a_block_to_paste_is_one_its_platform_declares(): void
    {
        $undeclared = [];

        foreach (HandWrittenPlatformBlock::CONNECTIONS as $platform => $connection) {
            $contents = (string) file_get_contents(\sprintf('%s/%s.php', self::PLATFORM_CONFIG_GLOB, $platform));

            foreach (array_keys($connection) as $setting) {
                if (1 !== preg_match(\sprintf('/Node\(\x27%s\x27\)/', $setting), $contents)) {
                    $undeclared[] = \sprintf('%s.%s', $platform, $setting);
                }
            }
        }

        self::assertSame([], $undeclared);
    }

    public function test_every_hand_written_platform_still_exists_in_the_bundle(): void
    {
        self::assertSame([], array_diff(array_keys(HandWrittenPlatforms::REQUIREMENTS), $this->platformNames()));
    }

    public function test_no_platform_requiring_an_extra_field_is_left_writable(): void
    {
        self::assertSame([], array_diff($this->platformsRequiringMoreThanACredential(), $this->platformsInitRefusesToWrite()));
    }

    public function test_no_platform_without_an_api_key_node_is_left_writable(): void
    {
        $withoutApiKey = array_values(array_diff($this->platformNames(), $this->platformsDeclaring('api_key')));

        self::assertSame([], array_diff($withoutApiKey, $this->platformsInitRefusesToWrite()));
    }

    /**
     * A platform whose connection block names another platform's service —
     * `cache` the one it caches, `failover` the ones it falls back through —
     * wraps platforms rather than reaching a provider.
     */
    public function test_every_platform_wrapping_another_is_named(): void
    {
        self::assertSame(array_keys(CompoundPlatforms::SERVICES_NEEDED), $this->platformsDeclaringAnyOf(['platform', 'platforms']));
    }

    public function test_no_platform_wrapping_another_is_offered_as_one_to_write_by_hand(): void
    {
        self::assertSame([], array_intersect(array_keys(CompoundPlatforms::SERVICES_NEEDED), array_keys(HandWrittenPlatforms::REQUIREMENTS)));
    }

    /**
     * @return list<string>
     */
    private function platformsInitRefusesToWrite(): array
    {
        return [...array_keys(HandWrittenPlatforms::REQUIREMENTS), ...array_keys(CompoundPlatforms::SERVICES_NEEDED)];
    }

    /**
     * @param list<string> $nodes
     *
     * @return list<string>
     */
    private function platformsDeclaringAnyOf(array $nodes): array
    {
        $names = [];
        $pattern = \sprintf('/Node\(\x27(?:%s)\x27\)/', implode('|', array_map(static fn (string $node): string => preg_quote($node, '/'), $nodes)));

        foreach ($this->configFiles() as $finder) {
            if (1 === preg_match($pattern, $finder->getContents())) {
                $names[] = $finder->getBasename('.php');
            }
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private function platformNames(): array
    {
        $names = [];

        foreach ($this->configFiles() as $finder) {
            $names[] = $finder->getBasename('.php');
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private function platformsDeclaring(string $node): array
    {
        $names = [];
        $pattern = \sprintf('/(?:string|scalar)Node\(\x27%s\x27\)/', preg_quote($node, '/'));

        foreach ($this->configFiles() as $finder) {
            if (1 === preg_match($pattern, $finder->getContents())) {
                $names[] = $finder->getBasename('.php');
            }
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private function platformsDeclaring_useAttributeAsKey(): array
    {
        $names = [];

        foreach ($this->configFiles() as $finder) {
            if (str_contains($finder->getContents(), 'useAttributeAsKey')) {
                $names[] = $finder->getBasename('.php');
            }
        }

        sort($names);

        return $names;
    }

    public function test_no_platform_is_refused_for_a_requirement_it_no_longer_has(): void
    {
        $refusedForAnExtraField = array_keys(array_filter(
            HandWrittenPlatforms::REQUIREMENTS,
            static fn (string $requirement): bool => !str_contains($requirement, 'rather than an api_key'),
        ));

        self::assertSame([], array_diff($refusedForAnExtraField, $this->platformsRequiringMoreThanACredential()));
    }

    /**
     * Platforms with a required child beyond the `api_key` and `base_url` that
     * `init` writes. Each node owns the chain from its own declaration up to
     * its `->end()`, so a later sibling's `->isRequired()` is not attributed to
     * a node that merely carries a default.
     *
     * @return list<string>
     */
    private function platformsRequiringMoreThanACredential(): array
    {
        $names = [];

        foreach ($this->configFiles() as $finder) {
            preg_match_all('/(?:string|scalar|integer|float|boolean|enum|variable|array)Node\(\x27([a-z_]+)\x27\)(.*?)->end\(\)/s', $finder->getContents(), $matches, \PREG_SET_ORDER);

            foreach ($matches as $match) {
                if (str_contains($match[2], '->isRequired()') && !\in_array($match[1], ['api_key', 'base_url'], true)) {
                    $names[] = $finder->getBasename('.php');
                    break;
                }
            }
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private function platformsDeclaringANodeWithoutADefault(string $node): array
    {
        $names = [];

        foreach ($this->configFiles() as $finder) {
            $declaration = $this->nodeDeclaration($finder->getContents(), $node);

            if (null !== $declaration && !str_contains($declaration, '->defaultValue(')) {
                $names[] = $finder->getBasename('.php');
            }
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private function platformsDeclaringAnOptionalApiKey(): array
    {
        $names = [];

        foreach ($this->configFiles() as $finder) {
            $declaration = $this->nodeDeclaration($finder->getContents(), 'api_key');

            if (null !== $declaration && !str_contains($declaration, '->isRequired()') && !$this->validationInsistsOnApiKey($finder->getContents())) {
                $names[] = $finder->getBasename('.php');
            }
        }

        sort($names);

        return $names;
    }

    /**
     * A node left optional in its own declaration can still be demanded by
     * the platform's `->validate()` closure — `vertexai` insists on `api_key`
     * unless a project-scoped endpoint is configured instead, which `init`
     * never writes.
     */
    private function validationInsistsOnApiKey(string $contents): bool
    {
        return 1 === preg_match('/->validate\(\)(.*?)->end\(\)/s', $contents, $matches) && str_contains($matches[1], 'api_key');
    }

    /**
     * The chain a node owns, from its own declaration up to its `->end()`, so a
     * later sibling's `->defaultValue()` or `->isRequired()` is never read as
     * belonging to it.
     */
    private function nodeDeclaration(string $contents, string $node): ?string
    {
        $pattern = \sprintf('/(?:string|scalar)Node\(\x27%s\x27\)(.*?)->end\(\)/s', preg_quote($node, '/'));

        return 1 === preg_match($pattern, $contents, $matches) ? $matches[1] : null;
    }

    private function configFiles(): Finder
    {
        return (new Finder())->files()->in(self::PLATFORM_CONFIG_GLOB)->name('*.php')->depth(0);
    }
}
