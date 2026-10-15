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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Pipeline;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class SinceClosureIntegrationTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_changed_voter_pulls_in_the_controllers_guarded_by_its_constants_and_by_its_literal(): void
    {
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Security/PostVoter.php']);
        $auditContext = AuditContext::forProject($this->tmpDir, diffSinceRef: 'main');

        (new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger(), $gitChangedFilesResolver))->process($auditContext);
        (new MappingStage(new NullLogger(), new PhpParserControllerAccessControlParser(), new PhpParserVoterCapabilityParser(), new PhpParserFormBindingParser(), new SymfonyYamlSecurityConfigParser(new NullLogger())))->process($auditContext);
        (new DependencyExpansionStage(new NullLogger(), 'direct'))->process($auditContext);

        self::assertSame(
            ['src/Security/PostVoter.php', 'src/Controller/CommentController.php', 'src/Controller/LitController.php', 'src/Controller/PostController.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditContext->projectFiles()),
        );
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/since_closure_'.uniqid('', true);
        $filesystem = new Filesystem();
        $filesystem->dumpFile($this->tmpDir.'/src/Security/PostVoter.php', <<<'PHP'
            <?php
            namespace App\Security;
            use Symfony\Component\Security\Core\Authorization\Voter\Voter;
            use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
            class PostVoter extends Voter
            {
                public const EDIT = 'POST_EDIT';
                public const VIEW = 'POST_VIEW';
                protected function supports(string $attribute, mixed $subject): bool { return \in_array($attribute, [self::EDIT], true); }
                protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool { return true; }
            }
            PHP);
        $filesystem->dumpFile($this->tmpDir.'/src/Controller/PostController.php', <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Security\PostVoter;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            class PostController extends AbstractController
            {
                #[Route('/post/{id}/edit')]
                #[IsGranted(PostVoter::EDIT, 'post')]
                public function edit() { return $this->json([]); }
            }
            PHP);
        $filesystem->dumpFile($this->tmpDir.'/src/Controller/CommentController.php', <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Security\PostVoter;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            class CommentController extends AbstractController
            {
                #[Route('/comment/{id}/edit')]
                public function edit($post) { $this->denyAccessUnlessGranted(PostVoter::EDIT, $post); return $this->json([]); }
            }
            PHP);
        $filesystem->dumpFile($this->tmpDir.'/src/Controller/LitController.php', <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            class LitController extends AbstractController
            {
                #[Route('/lit/{id}/edit')]
                #[IsGranted('POST_EDIT', 'post')]
                public function edit() { return $this->json([]); }
            }
            PHP);
        $filesystem->dumpFile($this->tmpDir.'/src/Controller/ViewController.php', <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Security\PostVoter;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            class ViewController extends AbstractController
            {
                #[Route('/post/{id}')]
                #[IsGranted(PostVoter::VIEW, 'post')]
                public function show() { return $this->json([]); }
            }
            PHP);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }
}
