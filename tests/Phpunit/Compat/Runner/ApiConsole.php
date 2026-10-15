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

use Override;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Scenario;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Step;

/**
 * The public PHP API, called the way an integration calls it: `api:models`
 * builds the Domain models through their public factories and reads every
 * accessor; `api:run-audit` calls `RunAuditUseCase::execute()` as wired by
 * the bundle, with the step input as its arguments.
 */
final readonly class ApiConsole implements ConsoleInterface
{
    private const int REPORT_DEPTH = 3;

    public function __construct(
        private Scenario $scenario,
        private Workspace $workspace,
    ) {}

    #[Override]
    public function run(Step $step): ConsoleRun
    {
        ConsoleTester::enter($step, $this->workspace);

        try {
            $snapshot = 'api:models' === $step->command ? DomainModelProbe::snapshot($this->workspace) : $this->runAudit($step);
        } catch (Throwable $throwable) {
            return new ConsoleRun(1, '', \sprintf('%s: %s', $throwable::class, $throwable->getMessage()));
        }

        return new ConsoleRun(0, (string) json_encode($snapshot, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_PRESERVE_ZERO_FRACTION), '');
    }

    /**
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    private function runAudit(Step $step): mixed
    {
        $kernel = (new BundleConsole($this->scenario, $this->workspace))->bootedKernel();
        $testContainer = $kernel->getContainer()->get('test.service_container');
        if (!$testContainer instanceof TestContainer) {
            throw new RuntimeException('The kernel exposes no test container.');
        }

        $runAuditUseCase = $testContainer->get(RunAuditUseCase::class);
        if (!$runAuditUseCase instanceof RunAuditUseCase) {
            throw new RuntimeException('The container holds no RunAuditUseCase.');
        }

        $input = $step->input;

        try {
            return AccessorSnapshot::of($runAuditUseCase->execute(
                $this->workspace->projectDir(),
                $this->strings($input['scan-paths'] ?? []),
                true === ($input['bypass-cache'] ?? false),
                \is_string($input['since'] ?? null) ? $input['since'] : null,
                $this->strings($input['accepted-fingerprints'] ?? []),
            ), self::REPORT_DEPTH);
        } finally {
            $kernel->shutdown();
        }
    }

    /**
     * @return list<string>
     */
    private function strings(mixed $value): array
    {
        return \is_array($value) ? array_values(array_filter($value, \is_string(...))) : [];
    }
}
