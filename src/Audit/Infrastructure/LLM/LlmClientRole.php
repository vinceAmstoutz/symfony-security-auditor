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

/**
 * The configuration of one LLM client the bundle wires: the setting its model comes from and whether the configuration sets an output cap for its role.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class LlmClientRole
{
    public function __construct(
        public ModelSetting $modelSetting,
        public bool $capsEveryModel,
    ) {}
}
