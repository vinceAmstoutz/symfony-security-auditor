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
 * The `init` console help text, kept out of the command class itself.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class InitCommandHelp
{
    public const string HELP = <<<'HELP'
        The <info>%command.name%</info> command writes the standalone configuration and downloads the provider bridge it needs.
        Every option it does not receive is asked for; under <info>--no-interaction</info> each falls back to its default instead.

        Defaults:
          <info>--provider</info>  anthropic
          <info>--model</info>     claude-opus-4-8 — set it for any other provider, it is not derived from one
          <info>--env-var</info>   &lt;PLATFORM&gt;_API_KEY

        A platform configured per instance needs the instance in <info>--provider</info>, and the endpoint it reaches in <info>--base-url</info>:

          <info>%command.name% --provider=openai --model=gpt-5.6 --no-interaction</info>
          <info>%command.name% --provider=generic.my_gateway --base-url=https://your-gateway.example --env-var=GATEWAY_TOKEN --model=your-model</info>

        <info>--base-url</info> is the origin only; the bridge appends its own path, so do not include a trailing <info>/v1</info>.
        HELP;
}
