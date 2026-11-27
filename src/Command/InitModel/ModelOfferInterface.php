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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel;

use Symfony\Component\Console\Style\SymfonyStyle;

/** @internal not part of the BC promise, see docs/versioning.md */
interface ModelOfferInterface
{
    /**
     * Returns the model the answer names, null where none can be asked for
     * without interaction.
     */
    public function ask(SymfonyStyle $symfonyStyle, bool $interactive): ?string;
}
