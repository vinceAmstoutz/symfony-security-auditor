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
 * The models a platform's own listing prices and that call tools, which the
 * auditor needs, for `init` to offer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface PricedModelListInterface
{
    /**
     * @return list<string> the newest first
     */
    public function pricedModels(string $platform): array;
}
