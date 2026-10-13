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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\Pricing;

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;

use function Symfony\Component\String\u;

/**
 * A model the docs recommend for a paid platform must carry a published price
 * in the packaged `symfony/models-dev` catalog: an unpriced one reports a
 * $0.00 cost, and a run with a cost budget refuses it as a likely typo.
 */
final class DocumentedModelPricingTest extends TestCase
{
    private const string MODEL_PICK_HEADING = '### Which LLM model should I use?';

    private const string CHEAPER_REVIEWER_ADVICE = '- Switch to a cheaper Reviewer';

    private const string LOCAL_RUNTIME = 'Ollama';

    private const string CONFIGURATION_KEY_PREFIX = '/^(?:model|attacker_model|reviewer_model): /';

    /** @var array<string, ModelsDevPricingProvider> */
    private static array $pricingProvidersByPlatform = [];

    #[DataProvider('recommendedModelCases')]
    public function test_every_model_the_docs_recommend_for_a_paid_platform_has_a_published_price(string $source, ?string $platform, string $model): void
    {
        $modelsDevPricingProvider = self::$pricingProvidersByPlatform[$platform ?? ''] ??= new ModelsDevPricingProvider(new NullLogger(), platform: $platform);

        self::assertTrue($modelsDevPricingProvider->hasModel($model), \sprintf('%s recommends `%s`, which the packaged symfony/models-dev catalog does not price.', $source, $model));
        self::assertGreaterThan(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens($model), \sprintf('%s recommends `%s` as a paid model, yet the catalog prices its input at zero.', $source, $model));
    }

    /**
     * @return array<string, array{string, ?string, string}>
     *
     * @throws JsonException
     */
    public static function recommendedModelCases(): array
    {
        $cases = [];
        foreach ([...self::modelPickTableModels(), ...self::cheaperReviewerModels()] as [$source, $model]) {
            $cases[\sprintf('%s: %s', $source, $model)] = [$source, null, $model];
        }

        foreach (self::suggestedBridgeModels() as [$platform, $model]) {
            $cases[\sprintf('composer.json suggest (%s): %s', $platform, $model)] = ['composer.json suggest', $platform, $model];
        }

        return $cases;
    }

    /**
     * The FAQ's model-pick table, but for the setup that runs a model on the
     * local machine, which costs nothing.
     *
     * @return list<array{string, string}>
     */
    private static function modelPickTableModels(): array
    {
        $faq = self::read('docs/faq.md');
        $table = u($faq)->after(self::MODEL_PICK_HEADING)->before("\n### ")->toString();
        $models = [];
        foreach (u($table)->split("\n") as $row) {
            if ($row->startsWith('| ') && !$row->containsAny(self::LOCAL_RUNTIME)) {
                $models = [...$models, ...self::backtickedModels('docs/faq.md', $row->toString())];
            }
        }

        return $models;
    }

    /**
     * @return list<array{string, string}>
     */
    private static function cheaperReviewerModels(): array
    {
        $troubleshooting = self::read('docs/troubleshooting.md');
        $advice = u($troubleshooting)->after(self::CHEAPER_REVIEWER_ADVICE)->before("\n")->toString();

        return self::backtickedModels('docs/troubleshooting.md', $advice);
    }

    /**
     * @return list<array{string, string}>
     */
    private static function backtickedModels(string $source, string $text): array
    {
        $models = [];
        foreach (array_values(u($text)->split('`')) as $index => $segment) {
            $model = $segment->replaceMatches(self::CONFIGURATION_KEY_PREFIX, '');
            if (1 === $index % 2 && !$model->containsAny(' ')) {
                $models[] = [$source, $model->toString()];
            }
        }

        return $models;
    }

    /**
     * The models `composer.json` names for each platform bridge it suggests
     * (`… — model-a, model-b`).
     *
     * @return list<array{string, string}>
     *
     * @throws JsonException
     */
    private static function suggestedBridgeModels(): array
    {
        $models = [];
        foreach (self::suggestedPaidBridges() as $platform => $description) {
            foreach (u($description)->after(' — ')->split(', ') as $item) {
                if (!$item->containsAny(' ') && [] !== $item->match('/[\d-]/')) {
                    $models[] = [$platform, $item->toString()];
                }
            }
        }

        return $models;
    }

    /**
     * The description of each platform bridge `composer.json` suggests, keyed
     * by the platform's name, but for the bridge that runs a model on the
     * local machine, which costs nothing.
     *
     * @return array<string, string>
     *
     * @throws JsonException
     */
    private static function suggestedPaidBridges(): array
    {
        $composerJson = json_decode(self::read('composer.json'), true, flags: \JSON_THROW_ON_ERROR);
        $suggest = \is_array($composerJson) && \is_array($composerJson['suggest'] ?? null) ? $composerJson['suggest'] : [];
        $bridges = [];
        foreach ($suggest as $package => $description) {
            $bridge = u((string) $package)->match('/^symfony\/ai-(.+)-platform$/')[1] ?? null;
            if (\is_string($bridge) && \is_string($description) && !u($description)->containsAny(self::LOCAL_RUNTIME)) {
                $bridges[u($bridge)->replace('-', '')->toString()] = $description;
            }
        }

        return $bridges;
    }

    private static function read(string $path): string
    {
        return (new Filesystem())->readFile(\sprintf('%s/%s', \dirname(__DIR__, 5), $path));
    }
}
