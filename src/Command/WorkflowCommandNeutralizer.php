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
 * On a GitHub Actions runner a report printed to the job log quotes the
 * audited code and what the model wrote about it, and an error message may
 * quote a checkout path; either could carry a workflow command. Each is
 * defused as its format allows, so a document piped into `jq` or redirected
 * into the step summary still reads the same: the JSON formats keep their
 * meaning byte for byte once decoded, the others only lose the markers, and
 * any byte that is not UTF-8 reads as `?`. The `github` format's annotations
 * are the ones meant for the runner.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
