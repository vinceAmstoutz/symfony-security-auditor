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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DryRunFootnote;

final class DryRunFootnoteTest extends TestCase
{
    #[DataProvider('footnotes')]
    public function test_it_explains_the_figures_of_a_dry_run_in_one_footnote(?int $reviewerRatioPercent, bool $onSubscription, string $footnote): void
    {
        self::assertSame($footnote, DryRunFootnote::of($reviewerRatioPercent, $onSubscription));
    }

    /**
     * @return iterable<string, array{?int, bool, string}>
     */
    public static function footnotes(): iterable
    {
        yield 'a priced run with a reviewer figure' => [5, false, 'No LLM call was made. The reviewer figure assumes ~5% of the attacker input. Prompt-cache discounts or warm caches usually make a real run cheaper.'];
        yield 'a priced run without a reviewer figure' => [null, false, 'No LLM call was made. Prompt-cache discounts or warm caches usually make a real run cheaper.'];
        yield 'a subscription with a reviewer figure' => [5, true, 'No LLM call was made. Your subscription is not billed per call, so no cost is shown. The reviewer figure assumes ~5% of the attacker input.'];
        yield 'a subscription without a reviewer figure' => [null, true, 'No LLM call was made. Your subscription is not billed per call, so no cost is shown.'];
    }
}
