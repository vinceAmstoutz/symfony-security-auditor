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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use Throwable;

/**
 * Marks the refusal of a prompt longer than the command line of a CLI can
 * carry, whatever the context window of the model behind it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface CommandLineLimitExceptionInterface extends Throwable {}
