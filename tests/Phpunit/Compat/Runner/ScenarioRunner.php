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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\CompatAutoloader;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\PlatformSession;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Runtime;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Scenario;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Step;

/**
 * Runs a scenario against whichever checkout the process autoloads and
 * returns what it observed, normalized: one entry per command (its exit code
 * and both output streams), the collected files, and the calls the scripted
 * provider received.
 */
final readonly class ScenarioRunner
{
    private const string FIXTURE_DIR = __DIR__.'/../Fixture';

    /**
     * Runs the preparing commands, keeps the artifacts they wrote, then
     * observes the scenario from a fresh workspace holding only those
     * artifacts, as a replay does: nothing else the preparation left behind
     * (a kernel cache, a warmed attacker cache) reaches the recording.
     *
     * @return array{artifacts: array<string, array{mode: string, base64: string}>, result: array<string, mixed>}
     */
    public function record(Scenario $scenario): array
    {
        $workspace = $this->workspaceFor($scenario);
        $console = $this->consoleFor($scenario, $workspace);

        PlatformSession::start($scenario->platform());
        foreach ($scenario->prepareSteps() as $step) {
            $console->run($step);
        }

        $artifacts = ArtifactStore::capture($workspace, $scenario->artifacts());
        chdir(\dirname(__DIR__));
        $workspace->remove();

        return ['artifacts' => $artifacts, 'result' => $this->replay($scenario, $artifacts)];
    }

    /**
     * @param array<string, array{mode: string, base64: string}> $artifacts
     *
     * @return array<string, mixed>
     */
    public function replay(Scenario $scenario, array $artifacts): array
    {
        CompatAutoloader::register();
        $workspace = $this->workspaceFor($scenario);

        try {
            ArtifactStore::restore($workspace, $artifacts);
            $this->applyChanges($scenario, $workspace);

            return $this->observe($scenario, $workspace, $this->consoleFor($scenario, $workspace));
        } finally {
            chdir(\dirname(__DIR__));
            $workspace->remove();
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function observe(Scenario $scenario, Workspace $workspace, ConsoleInterface $console): array
    {
        $normalizer = Normalizer::for($workspace);
        PlatformSession::start($scenario->platform());

        $runs = array_map(
            fn (Step $step): array => $this->observeRun($step, $console->run($step), $normalizer),
            $scenario->steps(),
        );

        $files = [];
        foreach ($scenario->collected() as $path) {
            $files[$path] = Snapshot::ofPath($workspace->resolve($path), $normalizer);
        }

        return ['runs' => $runs, 'files' => $files, 'llm' => ['lines' => array_map($normalizer->text(...), PlatformSession::calls())]];
    }

    /**
     * @return array<string, mixed>
     */
    private function observeRun(Step $step, ConsoleRun $consoleRun, Normalizer $normalizer): array
    {
        return [
            'command' => $normalizer->text($step->label()),
            'exit' => $consoleRun->exitCode,
            'stdout' => Snapshot::ofText($consoleRun->stdout, $normalizer),
            'stderr' => Snapshot::ofText($consoleRun->stderr, $normalizer),
        ];
    }

    private function workspaceFor(Scenario $scenario): Workspace
    {
        $workspace = Workspace::create();
        $filesystem = new Filesystem();
        $filesystem->copy(\sprintf('%s/bin/composer', self::FIXTURE_DIR), $workspace->resolve('bin/composer'));
        $filesystem->chmod($workspace->resolve('bin/composer'), 0o755);
        $filesystem->copy(\sprintf('%s/pricing-catalog.json', self::FIXTURE_DIR), $workspace->resolve('kernel/cache/models-dev.json'));
        $filesystem->copy(\sprintf('%s/pricing-catalog.json', self::FIXTURE_DIR), $workspace->resolve('home/cache/symfony-security-auditor/models-dev.json'));

        ProcessEnvironment::apply($workspace, [...StandaloneConsole::homeEnvironment(), ...$scenario->environment()]);

        foreach ($scenario->setup() as $setupAction) {
            $setupAction->apply($workspace);
        }

        return $workspace;
    }

    private function applyChanges(Scenario $scenario, Workspace $workspace): void
    {
        foreach ($scenario->changes() as $setupAction) {
            $setupAction->apply($workspace);
        }
    }

    private function consoleFor(Scenario $scenario, Workspace $workspace): ConsoleInterface
    {
        return match ($scenario->runtime) {
            Runtime::Bundle => new BundleConsole($scenario, $workspace),
            Runtime::Standalone => new StandaloneConsole($workspace),
            Runtime::Api => new ApiConsole($scenario, $workspace),
        };
    }
}
