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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\WorkflowCommandText;

/**
 * Defuses the workflow commands a report or an error message could carry on a
 * GitHub Actions runner, as each format allows: the JSON formats decode to the
 * same value, the others lose only the markers and read each byte that is not
 * UTF-8 as `?`. The `github` format is left as is.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class WorkflowCommandNeutralizer implements WorkflowCommandNeutralizerInterface
{
    private const array JSON_FORMATS = [OutputFormat::Json, OutputFormat::Sarif];

    public function __construct(
        private bool $onGithubActions,
    ) {}

    public static function fromEnvironment(): self
    {
        return new self('true' === getenv('GITHUB_ACTIONS'));
    }

    #[Override]
    public function report(OutputFormat $outputFormat, string $report): string
    {
        return match (true) {
            !$this->onGithubActions, OutputFormat::GithubAnnotations === $outputFormat => $report,
            \in_array($outputFormat, self::JSON_FORMATS, true) => WorkflowCommandText::inJson($report),
            default => WorkflowCommandText::inDocument($report),
        };
    }

    #[Override]
    public function message(string $message): string
    {
        return $this->onGithubActions ? WorkflowCommandText::inWrappedMessage($message) : $message;
    }
}
