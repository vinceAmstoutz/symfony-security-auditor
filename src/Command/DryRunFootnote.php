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
 * The one footnote under a dry-run estimate: no call was made and how the
 * reviewer figure is projected. It also says why a priced run costs less than
 * shown or why a subscription shows no cost.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class DryRunFootnote
{
    public static function of(?int $reviewerRatioPercent, bool $onSubscription): string
    {
        $sentences = ['No LLM call was made.'];

        if ($onSubscription) {
            $sentences[] = 'Your subscription is not billed per call, so no cost is shown.';
        }

        if (null !== $reviewerRatioPercent) {
            $sentences[] = \sprintf('The reviewer figure assumes ~%d%% of the attacker input.', $reviewerRatioPercent);
        }

        if (!$onSubscription) {
            $sentences[] = 'Prompt-cache discounts or warm caches usually make a real run cheaper.';
        }

        return implode(' ', $sentences);
    }
}
