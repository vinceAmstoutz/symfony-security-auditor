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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use Closure;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\PlatformScript;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;

/**
 * One recorded behaviour: a workspace (the audited project, a home, config
 * files), the commands run in it, and what is captured afterwards.
 *
 * The `prepare` commands run only when recording: the release being recorded
 * produces the `artifacts` (its reports, baselines, caches, configuration
 * files) and the recording keeps them, so a replay hands the tree under test
 * the very files that release wrote instead of its own.
 */
final readonly class Scenario
{
    /**
     * @param array{
     *     setup: list<SetupActionInterface>,
     *     changes: list<SetupActionInterface>,
     *     config: array<string, mixed>,
     *     platform: PlatformScript,
     *     prepare: list<Step>,
     *     steps: list<Step>,
     *     collect: list<string>,
     *     artifacts: list<string>,
     *     environment: array<string, string>,
     *     services: Closure(ContainerBuilder): void|null,
     *     deprecations: list<non-empty-string>,
     * } $definition
     */
    private function __construct(
        public string $name,
        public Runtime $runtime,
        private array $definition,
    ) {}

    public static function bundle(string $name): self
    {
        return self::create($name, Runtime::Bundle);
    }

    public static function standalone(string $name): self
    {
        return self::create($name, Runtime::Standalone);
    }

    public static function api(string $name): self
    {
        return self::create($name, Runtime::Api);
    }

    /**
     * @param array<string, string> $files contents by path, relative to the audited project
     */
    public function withProjectFiles(array $files): self
    {
        $actions = [];
        foreach ($files as $path => $content) {
            $actions[] = new WriteFile(\sprintf('project/%s', $path), $content);
        }

        return $this->withSetup(...$actions);
    }

    /**
     * @param array<string, string> $files contents by path, relative to the workspace
     */
    public function withFiles(array $files): self
    {
        $actions = [];
        foreach ($files as $path => $content) {
            $actions[] = new WriteFile($path, $content);
        }

        return $this->withSetup(...$actions);
    }

    public function withSetup(SetupActionInterface ...$setupActions): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'setup' => [...$this->definition['setup'], ...array_values($setupActions)]]);
    }

    /**
     * What changes in the workspace once the prepared artifacts are there, before
     * the commands under comparison run.
     */
    public function changingAfterPreparation(SetupActionInterface ...$setupActions): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'changes' => [...$this->definition['changes'], ...array_values($setupActions)]]);
    }

    /**
     * @param array<string, mixed> $config the bundle configuration (`symfony_security_auditor:`)
     */
    public function withConfig(array $config): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'config' => $config]);
    }

    public function withPlatform(PlatformScript $platformScript): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'platform' => $platformScript]);
    }

    /**
     * @param Closure(ContainerBuilder): void $services
     */
    public function withServices(Closure $services): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'services' => $services]);
    }

    /**
     * @param array<string, string> $environment
     */
    public function withEnvironment(array $environment): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'environment' => [...$this->definition['environment'], ...$environment]]);
    }

    public function preparing(Step ...$steps): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'prepare' => [...$this->definition['prepare'], ...array_values($steps)]]);
    }

    public function running(Step ...$steps): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'steps' => [...$this->definition['steps'], ...array_values($steps)]]);
    }

    public function collecting(string ...$paths): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'collect' => [...$this->definition['collect'], ...array_values($paths)]]);
    }

    public function keepingArtifacts(string ...$paths): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'artifacts' => [...$this->definition['artifacts'], ...array_values($paths)]]);
    }

    /**
     * The deprecations the scenario triggers on purpose, by calling a
     * deprecated part of the public API that must keep working.
     *
     * @param non-empty-string ...$messages
     */
    public function expectingDeprecations(string ...$messages): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'deprecations' => [...$this->definition['deprecations'], ...array_values($messages)]]);
    }

    /**
     * @return list<non-empty-string>
     */
    public function deprecations(): array
    {
        return $this->definition['deprecations'];
    }

    public function renamed(string $name): self
    {
        return new self($name, $this->runtime, $this->definition);
    }

    public function withoutSteps(): self
    {
        return new self($this->name, $this->runtime, [...$this->definition, 'steps' => []]);
    }

    /**
     * @return list<SetupActionInterface>
     */
    public function setup(): array
    {
        return [...($this->usesNullDevice() ? [new NullDevice()] : []), ...$this->definition['setup']];
    }

    /**
     * Whether a command writes to `{null-device}`: a release that replaces
     * its output file through a rename replaced the device itself, so such a
     * scenario is recorded only where that cannot reach the system's.
     */
    public function usesNullDevice(): bool
    {
        foreach ([...$this->definition['prepare'], ...$this->definition['steps']] as $step) {
            if ($step->mentions(Workspace::NULL_DEVICE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<SetupActionInterface>
     */
    public function changes(): array
    {
        return $this->definition['changes'];
    }

    /**
     * @return array<string, mixed>
     */
    public function config(): array
    {
        return $this->definition['config'];
    }

    public function platform(): PlatformScript
    {
        return $this->definition['platform'];
    }

    /**
     * @return (Closure(ContainerBuilder): void)|null
     */
    public function services(): ?Closure
    {
        return $this->definition['services'];
    }

    /**
     * @return array<string, string>
     */
    public function environment(): array
    {
        return $this->definition['environment'];
    }

    /**
     * @return list<Step>
     */
    public function prepareSteps(): array
    {
        return $this->definition['prepare'];
    }

    /**
     * @return list<Step>
     */
    public function steps(): array
    {
        return $this->definition['steps'];
    }

    /**
     * @return list<string>
     */
    public function collected(): array
    {
        return $this->definition['collect'];
    }

    /**
     * @return list<string>
     */
    public function artifacts(): array
    {
        return $this->definition['artifacts'];
    }

    private static function create(string $name, Runtime $runtime): self
    {
        return new self($name, $runtime, [
            'setup' => [],
            'changes' => [],
            'config' => [],
            'platform' => PlatformScript::default(),
            'prepare' => [],
            'steps' => [],
            'collect' => [],
            'artifacts' => [],
            'environment' => [],
            'services' => null,
            'deprecations' => [],
        ]);
    }
}
