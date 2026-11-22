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
use Symfony\AI\Platform\Exception\ModelNotFoundException;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;

/**
 * A CLI bridge lists a few models while its CLI takes any model id the
 * subscription offers, such as `claude-opus-5-5` or `gpt-5.5`: a name the
 * bridge does not list runs as a model of the same class as one it does, and
 * the CLI accepts or refuses it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CliAgentModelCatalog implements ModelCatalogInterface
{
    /**
     * @param non-empty-string $listedModel
     */
    public function __construct(
        private ModelCatalogInterface $modelCatalog,
        private string $listedModel,
    ) {}

    #[Override]
    public function getModel(string $modelName): Model
    {
        try {
            return $this->modelCatalog->getModel($modelName);
        } catch (ModelNotFoundException) {
            $listedModel = $this->modelCatalog->getModel($this->listedModel);
            $modelClass = $listedModel::class;

            return new $modelClass($modelName, $listedModel->getCapabilities());
        }
    }

    #[Override]
    public function getModels(): array
    {
        return $this->modelCatalog->getModels();
    }
}
