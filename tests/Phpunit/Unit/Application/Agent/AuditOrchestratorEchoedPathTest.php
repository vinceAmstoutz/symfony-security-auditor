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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\AuditOrchestratorHarness;

final class AuditOrchestratorEchoedPathTest extends TestCase
{
    private const string FILE_CONTENT = "<?php\n\$connection->query(\$id);\n";

    private string $tmpDir;

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('echoedPaths')]
    public function test_the_reviewer_is_given_the_code_of_a_file_whatever_way_the_attacker_spelled_its_path(string $echoedPath): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(filePath: $echoedPath)]),
            LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );
        $reviewerMessages = [];
        $reviewerLlm->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$reviewerMessages): LLMResponse {
            $reviewerMessages[] = $user;

            return AuditOrchestratorHarness::reviewerAcceptResponse();
        });

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($this->context());

        self::assertCount(1, $reviewerMessages);
        self::assertStringContainsString('$connection->query($id);', $reviewerMessages[0]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function echoedPaths(): iterable
    {
        yield 'as an absolute path' => ['/app/src/Controller/Foo.php'];
        yield 'with a leading slash' => ['/src/Controller/Foo.php'];
        yield 'with backslashes' => ['src\Controller\Foo.php'];
        yield 'with a leading dot slash' => ['./src/Controller/Foo.php'];
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_two_spellings_of_one_file_are_one_finding(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([
                AuditOrchestratorHarness::vulnerabilityPayload(filePath: 'src/Controller/Foo.php'),
                AuditOrchestratorHarness::vulnerabilityPayload(filePath: '/app/src/Controller/Foo.php'),
            ]),
            LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());
        $auditContext = $this->context();

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertSame(['src/Controller/Foo.php'], array_values(array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(), $auditContext->vulnerabilities())));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/orchestrator_echoed_path_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function context(): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([ProjectFile::create('src/Controller/Foo.php', '/app/src/Controller/Foo.php', self::FILE_CONTENT)]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        return $auditContext;
    }
}
