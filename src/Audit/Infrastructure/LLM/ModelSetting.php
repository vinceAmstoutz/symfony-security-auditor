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
 * The configuration setting a client's model comes from.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
enum ModelSetting: string
{
    case Model = 'model';
    case AttackerModel = 'attacker_model';
    case ReviewerModel = 'reviewer_model';
    case CheapModel = 'audit.escalation.cheap_model';

    /**
     * Returns this setting when it holds a model, else the one the model falls
     * back to.
     */
    public function ifSet(?string $model, self $fallback = self::Model): self
    {
        return null === $model ? $fallback : $this;
    }

    /**
     * Where to set a model the provider serves, in the standalone binary and
     * in a Symfony application.
     */
    public function advice(): string
    {
        $initOption = match ($this) {
            self::Model => ' or run init --model=<model id>',
            self::ReviewerModel => ' or run init --reviewer-model=<model id>',
            self::AttackerModel, self::CheapModel => '',
        };

        return \sprintf('Set %s: in the standalone config.yaml%s, or set symfony_security_auditor.%s in a Symfony application.', $this->value, $initOption, $this->value);
    }
}
