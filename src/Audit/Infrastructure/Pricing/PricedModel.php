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
 * A model `init` offers, with what a million tokens cost in US dollars.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PricedModel
{
    public function __construct(
        public string $id,
        public float $inputPrice,
        public ?float $outputPrice,
    ) {}
}
