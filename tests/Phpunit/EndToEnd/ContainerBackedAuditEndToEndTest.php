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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\MalformedResponseAuditPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\ScriptedAuditPlatform;

/**
 * Boots the real bundle through a Symfony kernel and drives `audit:run` from
 * the compiled container — the exact object graph `config/services.php` wires
 * for users — with only the `symfony/ai` platform replaced by the deterministic
 * {@see ScriptedAuditPlatform}. Unlike the hand-wired {@see FullAuditEndToEndTest},
 * this exercises `SymfonyAiLLMClient`, its retry/tool-loop/structured-collection
 * collaborators, and the DI defaults end to end, so production wiring drift and
 * report-schema drift both surface here.
 */
final class ContainerBackedAuditEndToEndTest extends TestCase
{
    private string $kernelDir;

    private string $fixtureDir;

    private ?Kernel $bootedKernel = null;

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_default_config_run_matches_the_committed_json_report_snapshot(): void
    {
        $report = $this->runAudit(['model' => 'gpt-4o'], 'json');

        self::assertSame(
            $this->snapshot('default-audit.json'),
            $this->normalizeJsonReport($report),
        );
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_default_config_run_matches_the_committed_sarif_report_snapshot(): void
    {
        $report = $this->runAudit(['model' => 'gpt-4o'], 'sarif');

        self::assertSame(
            $this->snapshot('default-audit.sarif.json'),
            $this->normalizeSarifReport($report),
        );
    }

    /**
     * Golden-masters every remaining `--format` renderer (console, executive,
     * html, markdown, junit, github, github-comment) written via `--output` — the clean
     * renderer output, free of presenter chrome and streamed progress — so a
     * change to any output format surfaces as a snapshot diff.
     */
    #[DataProvider('textReportFormatCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_default_config_run_matches_the_committed_text_report_snapshot(string $format, string $snapshot): void
    {
        self::assertSame(
            trim((string) file_get_contents(__DIR__.'/__snapshots__/'.$snapshot)),
            trim($this->normalizeTextReport($this->renderToFile(['model' => 'gpt-4o'], $format))),
        );
    }

    /** @return iterable<string, array{string, string}> */
    public static function textReportFormatCases(): iterable
    {
        yield 'console' => ['console', 'default-audit.console.txt'];
        yield 'executive' => ['executive', 'default-audit.executive.txt'];
        yield 'html' => ['html', 'default-audit.html'];
        yield 'markdown' => ['markdown', 'default-audit.markdown.txt'];
        yield 'junit' => ['junit', 'default-audit.junit.xml'];
        yield 'github' => ['github', 'default-audit.github.txt'];
        yield 'github-comment' => ['github-comment', 'default-audit.github-comment.txt'];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('configMatrixCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_seeded_finding_survives_every_wiring_combination(array $config): void
    {
        $report = $this->decode($this->runAudit(['model' => 'gpt-4o', ...$config], 'json'));

        self::assertSame(1, $report['total_vulnerabilities']);
    }

    /**
     * Each row swaps a different implementation behind the same public surface:
     * lean pre-scan + concurrency (`fast`), PoC synthesis (`thorough`), the
     * JSON-array collection fallback (attacker and reviewer), and batched
     * reviews. All must still surface — and validate — the seeded finding.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function configMatrixCases(): iterable
    {
        yield 'fast profile (lean pre-scan + concurrency)' => [['profile' => 'fast']];
        yield 'thorough profile (poc synthesis)' => [['profile' => 'thorough']];
        yield 'json collection (attacker + reviewer)' => [['audit' => ['structured_collection' => false, 'reviewer_structured_collection' => false]]];
        yield 'json reviewer via explicit tools opt-out' => [['audit' => ['reviewer_structured_collection' => false, 'reviewer_tools_enabled' => false]]];
        yield 'batched reviews' => [['audit' => ['reviewer_batch_size' => 3]]];
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_cache_preserves_the_findings_across_a_second_run(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        $first = $this->normalizeFindings($this->execute($kernel, 'json'));
        $second = $this->normalizeFindings($this->execute($kernel, 'json'));

        self::assertSame($first, $second);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_the_second_run_is_served_from_the_attacker_cache(): void
    {
        $kernel = $this->boot(['model' => 'gpt-4o', 'cache' => ['enabled' => true]]);

        $this->execute($kernel, 'json');
        $secondRun = $this->decode($this->execute($kernel, 'json'));

        /** @var list<array{stage: string, status: string}> $coverage */
        $coverage = $secondRun['coverage'];
        self::assertContains('cached', array_column($coverage, 'status'));
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('collectionModeCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(8000)]
    public function test_a_provider_that_ignores_the_output_contract_degrades_to_a_finding_free_audit(array $config): void
    {
        $report = $this->decode($this->runAudit(['model' => 'gpt-4o', ...$config], 'json', MalformedResponseAuditPlatform::class));

        self::assertSame(0, $report['total_vulnerabilities']);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function collectionModeCases(): iterable
    {
        yield 'structured collection (tool calls)' => [[]];
        yield 'json collection (array fallback)' => [['audit' => ['structured_collection' => false, 'reviewer_structured_collection' => false]]];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function normalizeFindings(string $report): array
    {
        $decoded = $this->decode($report);

        /** @var list<array<string, mixed>> $findings */
        $findings = $decoded['vulnerabilities'];

        return $this->stampTimestamps($findings);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function normalizeJsonReport(string $report): array
    {
        $decoded = $this->decode($report);
        $decoded['audit_id'] = 'AUDIT-XXXXXXXX';
        $decoded['project'] = 'PROJECT_PATH';
        $decoded['started_at'] = 'TIMESTAMP';
        $decoded['completed_at'] = 'TIMESTAMP';
        $decoded['duration_seconds'] = 'DURATION';

        /** @var list<array<string, mixed>> $vulnerabilities */
        $vulnerabilities = $decoded['vulnerabilities'];
        $decoded['vulnerabilities'] = $this->stampTimestamps($vulnerabilities);

        return $decoded;
    }

    /**
     * @param list<array<string, mixed>> $findings
     *
     * @return list<array<string, mixed>>
     */
    private function stampTimestamps(array $findings): array
    {
        return array_map(
            static fn (array $finding): array => [...$finding, 'detected_at' => 'TIMESTAMP'],
            $findings,
        );
    }

    /**
     * @return array<array-key, mixed>
     */
    private function normalizeSarifReport(string $report): array
    {
        /** @var array{runs: list<array{tool: array{driver: array<string, mixed>}}>} $decoded */
        $decoded = $this->decode($report);
        $decoded['runs'][0]['tool']['driver']['version'] = 'VERSION';

        return $decoded;
    }

    /**
     * Compares against the decoded snapshot rather than raw bytes, so the
     * committed file stays free to be Prettier-formatted without breaking the
     * assertion — the report's structure and values are what the golden master
     * pins.
     *
     * @return array<array-key, mixed>
     */
    private function snapshot(string $name): array
    {
        $decoded = json_decode((string) file_get_contents(__DIR__.'/__snapshots__/'.$name), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function decode(string $report): array
    {
        $start = strpos($report, '{');
        $end = strrpos($report, '}');
        self::assertIsInt($start);
        self::assertIsInt($end);

        $decoded = json_decode(substr($report, $start, $end - $start + 1), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * @param array<string, mixed>            $config
     * @param class-string<PlatformInterface> $platformClass
     */
    private function runAudit(array $config, string $format, string $platformClass = ScriptedAuditPlatform::class): string
    {
        return $this->execute($this->boot($config, $platformClass), $format);
    }

    private function execute(Kernel $kernel, string $format): string
    {
        $commandTester = new CommandTester($this->auditCommand($kernel));
        $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => $format]);

        return $commandTester->getDisplay();
    }

    /**
     * Renders through `--output` so the returned string is the renderer's file
     * output alone — no presenter header or streamed progress to strip.
     *
     * @param array<string, mixed> $config
     */
    private function renderToFile(array $config, string $format): string
    {
        $outputFile = $this->fixtureDir.'/report.out';
        $commandTester = new CommandTester($this->auditCommand($this->boot($config)));
        $commandTester->execute(['project-path' => $this->fixtureDir, '--format' => $format, '--output' => $outputFile]);

        return (string) file_get_contents($outputFile);
    }

    private function auditCommand(Kernel $kernel): AuditCommand
    {
        $testContainer = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);
        $auditCommand = $testContainer->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);

        return $auditCommand;
    }

    private function normalizeTextReport(string $report): string
    {
        $normalized = str_replace($this->fixtureDir, 'PROJECT_PATH', $report);
        $normalized = (string) preg_replace('/AUDIT-[0-9A-F]{8}/', 'AUDIT-XXXXXXXX', $normalized);
        $normalized = (string) preg_replace('/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', 'TIMESTAMP', $normalized);

        return (string) preg_replace('/\d+\.\d+s/', 'DURATIONs', $normalized);
    }

    /**
     * @param array<string, mixed>            $bundleConfig
     * @param class-string<PlatformInterface> $platformClass
     */
    private function boot(array $bundleConfig, string $platformClass = ScriptedAuditPlatform::class): Kernel
    {
        $kernel = new class('test', true, $this->kernelDir, $bundleConfig, $platformClass) extends Kernel {
            /**
             * @param array<string, mixed>            $bundleConfig
             * @param class-string<PlatformInterface> $platformClass
             */
            public function __construct(string $environment, bool $debug, private readonly string $kernelDir, private readonly array $bundleConfig, private readonly string $platformClass)
            {
                parent::__construct($environment, $debug);
            }

            /**
             * @return iterable<FrameworkBundle|SymfonySecurityAuditorBundle>
             */
            #[Override]
            public function registerBundles(): iterable
            {
                yield new FrameworkBundle();
                yield new SymfonySecurityAuditorBundle();
            }

            #[Override]
            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $bundleConfig = $this->bundleConfig;
                $platformClass = $this->platformClass;
                $loader->load(static function (ContainerBuilder $containerBuilder) use ($bundleConfig, $platformClass): void {
                    $containerBuilder->loadFromExtension('framework', [
                        'secret' => 'test',
                        'http_method_override' => false,
                        'handle_all_throwables' => true,
                        'test' => true,
                        'validation' => ['email_validation_mode' => 'html5'],
                        'php_errors' => ['log' => true],
                    ]);
                    $containerBuilder->loadFromExtension('symfony_security_auditor', $bundleConfig);
                    $containerBuilder->register(PlatformInterface::class, $platformClass)->setPublic(true);
                });
            }

            #[Override]
            public function getProjectDir(): string
            {
                return $this->kernelDir;
            }

            #[Override]
            public function getCacheDir(): string
            {
                return $this->kernelDir.'/cache';
            }

            #[Override]
            public function getLogDir(): string
            {
                return $this->kernelDir.'/log';
            }
        };

        $kernel->boot();

        $this->bootedKernel = $kernel;

        return $kernel;
    }

    #[Override]
    protected function setUp(): void
    {
        $base = sys_get_temp_dir().'/container_e2e_'.uniqid('', true);
        $this->kernelDir = $base.'/kernel';
        $this->fixtureDir = $base.'/fixture';

        $filesystem = new Filesystem();
        $filesystem->mkdir([$this->kernelDir, $this->fixtureDir.'/src/Controller', $this->fixtureDir.'/src/Service', $this->fixtureDir.'/config']);

        $filesystem->dumpFile(
            $this->fixtureDir.'/src/Controller/AdminController.php',
            <<<'PHP'
                <?php
                namespace App\Controller;
                use Symfony\Component\HttpFoundation\Response;
                class AdminController
                {
                    public function delete(): Response
                    {
                        // SECURITY_AUDITOR_SINK
                        $payload = unserialize($_GET['payload']);

                        return new Response('deleted '.$payload);
                    }
                }
                PHP,
        );

        $filesystem->dumpFile(
            $this->fixtureDir.'/src/Service/Clean.php',
            <<<'PHP'
                <?php
                namespace App\Service;
                class Clean
                {
                    public function add(int $a, int $b): int
                    {
                        return $a + $b;
                    }
                }
                PHP,
        );

        $filesystem->dumpFile(
            $this->fixtureDir.'/config/security.yaml',
            "security:\n  firewalls:\n    main:\n      pattern: ^/\n",
        );
    }

    #[Override]
    protected function tearDown(): void
    {
        if ($this->bootedKernel instanceof Kernel) {
            $this->bootedKernel->shutdown();
            $this->bootedKernel = null;
        }

        $filesystem = new Filesystem();
        $base = \dirname($this->kernelDir);
        if ($filesystem->exists($base)) {
            $filesystem->remove($base);
        }
    }
}
