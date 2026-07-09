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
 * The `audit:run` console help text, kept out of the command class itself.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class AuditCommandHelp
{
    public const string HELP = <<<'HELP'
        The <info>%command.name%</info> command runs a multi-agent LLM security audit against a Symfony project.
        By default it audits the current working directory; pass a path to audit a different project (e.g. <info>%command.full_name% /path/to/project</info>).

        Output formats (<info>--format</info>, <info>-f</info>):
          <info>console</info>  human-readable summary (default)
          <info>json</info>     machine-readable report
          <info>sarif</info>    SARIF 2.1.0 for GitHub Code Scanning / GitLab Security Dashboard
          <info>html</info>     self-contained HTML report for sharing or archiving
          <info>markdown</info> Markdown report for a PR comment or GitHub step summary
          <info>junit</info>    JUnit XML — findings as failed test cases for CI test-report panels (e.g. GitLab free-tier MR widgets)
          <info>github</info>   GitHub Actions workflow-command annotations — inline findings on the PR's Files Changed view

        Use <info>--output</info> (<info>-o</info>) to write the report to a file:
          <info>%command.full_name% --format=sarif --output=report.sarif</info>
          <info>%command.full_name% --format=html --output=report.html</info>

        Baseline (suppress accepted findings):
          <info>%command.full_name% --generate-baseline=.security-baseline.json</info>  accept current findings
          <info>%command.full_name% --baseline=.security-baseline.json</info>           suppress them on later runs
        Baselined findings are dropped from the report and do not affect the exit code.

        Exit codes (the failure threshold is configurable via <info>audit.fail_on</info> / <info>--fail-on</info>, default <info>critical</info>):
          <info>0</info>  audit completed; risk level is below the fail-on threshold
          <info>1</info>  audit completed with risk level at or above the fail-on threshold, or the audit itself failed
          <info>2</info>  audit budget could not be honored: it aborted mid-run because the configured token or cost budget was
                exceeded (partial report still emitted), or it never started because an unpriced model makes the cost
                budget unenforceable and the run was declined or non-interactive (no report emitted in that case)

        Cost & duration: a typical Symfony project (~150 files) takes minutes, not seconds,
        and costs a few cents to a few dollars depending on the selected model. Configure
        via <info>config/packages/symfony_security_auditor.yaml</info>.

        Documentation:
          Configuration : <info>docs/configuration.md</info>
          CI integration: <info>docs/ci.md</info>
          Versioning    : <info>docs/versioning.md</info>
        HELP;
}
