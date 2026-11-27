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

/**
 * The `audit:run` console help text.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AuditCommandHelp
{
    public const string HELP = <<<'HELP'
        The <info>%command.name%</info> command audits the project in the current directory, or the one you name:
          <info>%command.full_name% /path/to/project</info>
        A folder inside a Composer project audits that project, narrowed to the folder.

        Formats (<info>--format</info>, <info>-f</info>):
          <info>console</info>         summary in the terminal (default)
          <info>executive</info>       risk overview for stakeholders, without per-finding detail
          <info>json</info>            machine-readable report
          <info>sarif</info>           SARIF 2.1.0 for GitHub Code Scanning or the GitLab Security Dashboard
          <info>html</info>            self-contained page to share or archive
          <info>markdown</info>        report for a pull-request comment or a GitHub step summary
          <info>junit</info>           findings as failed tests, for CI test-report panels
          <info>github</info>          inline annotations on the pull request's changed files
          <info>github-comment</info>  pull-request comment a workflow can keep up to date
        Without <info>--format</info>, <info>audit.format</info> sets it, else the <info>--output</info> extension:
        <info>.html</info>, <info>.json</info>, <info>.sarif</info>, <info>.md</info>, <info>.xml</info> (junit), else <info>console</info>. A name without one is deprecated.

        Examples:
          <info>%command.full_name% --dry-run</info>                          estimate the cost first
          <info>%command.full_name% -f sarif -o report.sarif</info>           write a SARIF report
          <info>%command.full_name% --generate-baseline=baseline.json</info>  accept the current findings
          <info>%command.full_name% --baseline=baseline.json</info>           then report only new ones
        <info>--no-output</info> prints the report when <info>audit.output</info> names a file.

        Exit codes:
          <info>0</info>  risk below <info>--fail-on</info> (default <info>critical</info>) and score at or above <info>--min-score</info>,
             or <info>--generate-baseline</info> wrote its baseline, whatever the findings
          <info>1</info>  a gate tripped, the audit failed, or no verdict: no file found, or none analyzed and no finding
          <info>2</info>  a token or cost budget stopped the run (partial report), or an unpriced model
             made the cost budget unenforceable and the run never started (no report)
          <info>3</info>  <info>--fail-on-incomplete</info> and some file could not be fully analyzed; without it, a warning

        An audit takes minutes and costs cents to a few dollars, depending on the model.
        Configure it via <info>config/packages/symfony_security_auditor.yaml</info>.
        Docs: <info>https://github.com/vinceAmstoutz/symfony-security-auditor/tree/main/docs</info>
        HELP;

    private const string BUNDLE_CONFIGURATION = 'via <info>config/packages/symfony_security_auditor.yaml</info>.';

    private const string STANDALONE_CONFIGURATION = "via the <info>config.yaml</info> <info>init</info> writes, or a <info>.symfony-security-auditor.yaml</info>\nin the folder you run from or in the project.";

    /**
     * Names the files the binary reads in place of `config/packages/`.
     */
    public static function standalone(): string
    {
        return str_replace(self::BUNDLE_CONFIGURATION, self::STANDALONE_CONFIGURATION, self::HELP);
    }
}
