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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing;

/**
 * The priced, tool-calling models of a platform's own listing, for `init` to
 * offer.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface PricedModelListInterface
{
    /**
     * @return list<PricedModel> the most expensive first
     */
    public function pricedModels(string $platform): array;
}
