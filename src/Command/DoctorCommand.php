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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/** @internal not part of the BC promise — the command *name* (`doctor`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class DoctorCommand
{
    public const string NAME = 'doctor';

    public const string DESCRIPTION = 'Check that the environment is ready to run an audit';

    private const string CONNECTION_CHECK = 'Connection';

    public function __construct(
        private EnvironmentDoctorInterface $environmentDoctor,
        private ConnectionCheckInterface $connectionCheck,
    ) {}

    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Option(description: 'Also send one short request to the configured provider, which it may bill')] bool $checkConnection = false,
    ): int {
        $results = $this->environmentDoctor->diagnose();
        if ($checkConnection) {
            $results[] = $this->connectionResult();
        }

        foreach ($results as $result) {
            $this->render($symfonyStyle, $result);
        }

        return $this->containsFailure($results) ? Command::FAILURE : Command::SUCCESS;
    }

    private function connectionResult(): DoctorCheckResult
    {
        $failureReason = $this->connectionCheck->failureReason();

        return null === $failureReason
            ? new DoctorCheckResult(self::CONNECTION_CHECK, DoctorCheckStatus::Ok, 'It works. You can run an audit now.')
            : new DoctorCheckResult(self::CONNECTION_CHECK, DoctorCheckStatus::Failure, \sprintf(ConnectionProbe::FAILURE, $failureReason));
    }

    private function render(SymfonyStyle $symfonyStyle, DoctorCheckResult $doctorCheckResult): void
    {
        $line = \sprintf('%s: %s', $doctorCheckResult->label, $doctorCheckResult->detail);

        match ($doctorCheckResult->status) {
            DoctorCheckStatus::Ok => $symfonyStyle->writeln(\sprintf('<info>[OK]</info> %s', $line)),
            DoctorCheckStatus::Warning => $symfonyStyle->warning($line),
            DoctorCheckStatus::Failure => $symfonyStyle->error($line),
        };
    }

    /**
     * @param list<DoctorCheckResult> $results
     */
    private function containsFailure(array $results): bool
    {
        return [] !== array_filter(
            $results,
            static fn (DoctorCheckResult $doctorCheckResult): bool => DoctorCheckStatus::Failure === $doctorCheckResult->status,
        );
    }
}
