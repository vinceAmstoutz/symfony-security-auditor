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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\UseCase;

use LogicException;
use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class EstimateAuditCostUseCaseMappingOverheadTest extends TestCase
{
    private const string MODEL = 'claude-sonnet-4-5';

    private string $projectDir;

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws BudgetExceededException
     */
    public function test_the_estimate_of_a_route_heavy_project_is_within_a_factor_of_two_of_the_prompts_a_run_sends(): void
    {
        $realInputTokens = $this->inputTokensOfOneAttackerIteration();

        $estimatedInputTokens = $this->estimatedAttackerInputTokens();

        self::assertGreaterThanOrEqual($realInputTokens * 0.9, $estimatedInputTokens);
        self::assertLessThanOrEqual($realInputTokens * 2, $estimatedInputTokens);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws BudgetExceededException
     */
    public function test_the_estimate_of_a_path_scoped_run_prices_the_mapping_of_the_routes_outside_the_path(): void
    {
        $realInputTokens = $this->inputTokensOfOneAttackerIteration(['src/Service']);

        $estimatedInputTokens = $this->estimatedAttackerInputTokens(['src/Service']);

        self::assertGreaterThanOrEqual($realInputTokens * 0.9, $estimatedInputTokens);
        self::assertLessThanOrEqual($realInputTokens * 2, $estimatedInputTokens);
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws BudgetExceededException
     */
    private function inputTokensOfOneAttackerIteration(array $scanPaths = []): int
    {
        $llmClient = new class(new ResolvingTokenEstimator(), self::MODEL) implements LLMClientInterface {
            public int $inputTokens = 0;

            public function __construct(private readonly ResolvingTokenEstimator $resolvingTokenEstimator, private readonly string $model) {}

            /**
             * @throws InvalidTokenUsageException
             */
            #[Override]
            public function complete(string $systemPrompt, string $userMessage): LLMResponse
            {
                $this->inputTokens += $this->resolvingTokenEstimator->estimateTokens($systemPrompt, $this->model) + $this->resolvingTokenEstimator->estimateTokens($userMessage, $this->model);

                return LLMResponse::of('[]', $this->model, 'end_turn', TokenUsageSnapshot::of(1, 1));
            }

            /**
             * @throws InvalidTokenUsageException
             */
            #[Override]
            public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxIterations): LLMResponse
            {
                return $this->complete($systemPrompt, $userMessage);
            }

            #[Override]
            public function model(): string
            {
                return $this->model;
            }
        };

        $nullLogger = new NullLogger();
        $auditContext = AuditContext::forProject($this->projectDir, $scanPaths);
        (new IngestionStage(new ProjectFileScanner($nullLogger), $nullLogger))->process($auditContext);
        $this->mappingStage()->process($auditContext);
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators($llmClient, new AttackerPromptBuilder(false), new VulnerabilityFactory($nullLogger, Validation::createValidator()), new NullCodeSlicer()),
            new AttackerScanCollaborators(new NullAttackerCache(), new NullStaticPreScanner(), new NullProgressReporter()),
            new AttackerAnalysisSettings(useStructuredCollection: false),
            $nullLogger,
        );
        $attackerAgent->analyze(new AttackerAnalysisRequest($auditContext->projectFiles(), $auditContext->mapping() ?? throw new LogicException('The mapping stage maps nothing.')), $auditContext);

        return $llmClient->inputTokens;
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    private function estimatedAttackerInputTokens(array $scanPaths = []): int
    {
        $nullLogger = new NullLogger();
        $estimateAuditCostUseCase = new EstimateAuditCostUseCase(
            new ProjectFileScanner($nullLogger),
            new ResolvingTokenEstimator(),
            new CostCalculator($this->zeroPricing()),
            $nullLogger,
            new FileChunker(),
            new AttackerSkillRegistry(),
            self::MODEL,
            1,
            emitAllSkills: false,
            toolsEnabled: false,
            attackerPromptBuilder: new AttackerPromptBuilder(false),
            mappingStage: $this->mappingStage(),
        );

        return $estimateAuditCostUseCase->execute($this->projectDir, $scanPaths)->cost()->byRole()['attacker']['input_tokens'];
    }

    private function mappingStage(): MappingStage
    {
        $nullLogger = new NullLogger();

        return new MappingStage($nullLogger, new PhpParserControllerAccessControlParser(), new PhpParserVoterCapabilityParser(), new PhpParserFormBindingParser(), new SymfonyYamlSecurityConfigParser($nullLogger));
    }

    private function zeroPricing(): PricingProviderInterface
    {
        return new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/estimate_mapping_'.uniqid('', true);
        $filesystem = new Filesystem();
        for ($controller = 0; $controller < 4; ++$controller) {
            $routes = '';
            for ($route = 0; $route < 30; ++$route) {
                $routes .= \sprintf("    #[Route('/api/v1/feature%d/resource%d/{id}', methods: ['GET'])]\n    public function action%d(int \$id): Response { return new Response('x'); }\n", $controller, $route, $route);
            }

            $filesystem->dumpFile(\sprintf('%s/src/Controller/F%dController.php', $this->projectDir, $controller), \sprintf("<?php\nnamespace App\\Controller;\nuse Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;\nuse Symfony\\Component\\HttpFoundation\\Response;\nuse Symfony\\Component\\Routing\\Attribute\\Route;\nclass F%dController extends AbstractController\n{\n%s}\n", $controller, $routes));
        }

        for ($service = 0; $service < 60; ++$service) {
            $filesystem->dumpFile(\sprintf('%s/src/Service/Service%d.php', $this->projectDir, $service), \sprintf("<?php\nnamespace App\\Service;\nfinal class Service%d\n{\n    public function run(): int\n    {\n        return %d;\n    }\n}\n", $service, $service));
        }
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }
}
