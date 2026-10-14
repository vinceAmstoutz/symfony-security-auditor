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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;

/**
 * A client that books the usage of its answers itself — the bundled client,
 * or one the bundle wrapped to book it — so it is never wrapped again, even
 * when one client id is wired to the other.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface UsageBookingLLMClientInterface extends LLMClientInterface {}
