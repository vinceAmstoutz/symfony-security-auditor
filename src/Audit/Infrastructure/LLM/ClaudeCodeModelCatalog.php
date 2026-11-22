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

use Override;
use Symfony\AI\Platform\Bridge\ClaudeCode\ClaudeCode;
use Symfony\AI\Platform\Bridge\ClaudeCode\ModelCatalog;
use Symfony\AI\Platform\Exception\ModelNotFoundException;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;

/**
 * The bridge lists the Claude Code aliases only, while the CLI also takes a
 * full model id such as `claude-opus-5-5`: any name it does not list runs as
 * a Claude Code model too, and the CLI accepts or refuses it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ClaudeCodeModelCatalog implements ModelCatalogInterface
{
    private const string LISTED_MODEL = 'opus';

    public function __construct(
        private ModelCatalog $modelCatalog = new ModelCatalog(),
    ) {}

    #[Override]
    public function getModel(string $modelName): Model
    {
        try {
            return $this->modelCatalog->getModel($modelName);
        } catch (ModelNotFoundException) {
            return new ClaudeCode($modelName, $this->modelCatalog->getModel(self::LISTED_MODEL)->getCapabilities());
        }
    }

    #[Override]
    public function getModels(): array
    {
        return $this->modelCatalog->getModels();
    }
}
