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
 * What to say about models no price covers: on a subscription, that it is not
 * priced per call, never that the model name may be a typo.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class UnpricedModelNotice
{
    /**
     * @param list<string> $models
     */
    public static function forEstimate(array $models): string
    {
        return \sprintf('No published pricing for the configured model(s): %s. The dry-run cost estimate shows $0.00 for these. If you are running a local or self-hosted model (e.g. Ollama, LM Studio), $0.00 is correct — you can ignore this notice. Otherwise the name is likely a typo or an unlisted model: check it in your symfony_security_auditor configuration against the models supported by your symfony/ai platform.', implode(', ', $models));
    }

    /**
     * @param list<string> $models
     */
    public static function forRun(array $models, ?string $cliAgent): string
    {
        return null === $cliAgent
            ? \sprintf('No published pricing for the configured model(s): %s. Cost reporting will show $0.00 for these — correct for local or self-hosted models (e.g. Ollama, LM Studio); otherwise the name is likely a typo or an unlisted model.', implode(', ', $models))
            : \sprintf('The audit runs on a subscription through %s, which is not priced per call: cost reporting shows $0.00.', ProviderNames::ofPlatform($cliAgent));
    }

    public static function forBudgetRefusal(?string $cliAgent): string
    {
        return null === $cliAgent
            ? 'Refusing to start a budgeted audit with an unpriceable model in non-interactive mode. Configure a model with published pricing, or remove audit.budget.max_cost_usd.'
            : 'Refusing to start a budgeted audit in non-interactive mode. A subscription is not priced per call, so the cost budget cannot hold. Remove audit.budget.max_cost_usd to run on it.';
    }
}
