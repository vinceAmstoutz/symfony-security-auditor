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
        Every option it does not receive is asked for. Under <info>--no-interaction</info> the ones with defaults fall back to them, and a platform that requires a <info>--base-url</info> or an <info>--endpoint</info> is refused rather than written half-configured.

        Defaults:
          <info>--provider</info>  anthropic
          <info>--model</info>     claude-opus-4-8 — set it for any other provider, it is not derived from one
          <info>--env-var</info>   <PLATFORM>_API_KEY, except for a platform you host yourself, which is written without a credential unless you name one

        A platform configured per instance needs the instance in <info>--provider</info>, and the endpoint it reaches in <info>--base-url</info>:

          <info>%command.name% --provider=openai --model=gpt-5.6 --no-interaction</info>
          <info>%command.name% --provider=generic.my_gateway --base-url=https://your-gateway.example --env-var=GATEWAY_TOKEN --model=your-model</info>
          <info>%command.name% --provider=ollama --endpoint=http://localhost:11434 --model=llama3.2 --no-interaction</info>

        A platform spells its connection URL one way or the other, never both: <info>--base-url</info> for albert, amazeeai, generic and openresponses, <info>--endpoint</info> for deepgram, elevenlabs, minimax and ollama. Either is the origin only; the bridge appends its own path, so do not include a trailing <info>/v1</info>.
        <info>--no-api-key</info> writes no credential at all, for the platforms whose key the bundle leaves optional. Ollama takes that route by default, since a local install authenticates nobody.
        HELP;
}
