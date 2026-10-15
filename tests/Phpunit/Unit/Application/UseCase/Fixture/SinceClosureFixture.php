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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture;

use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\SinceClosurePreview;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

/**
 * A voter, the controller it guards and an unrelated one, and the preview of
 * a `--since` run widened by `audit.since_closure`, mapped by the real parsers.
 *
 * @internal scoped to the ListScannedFilesUseCase and EstimateAuditCostUseCase tests
 */
final class SinceClosureFixture
{
    public const string VOTER = <<<'PHP'
        <?php
        namespace App\Security;
        use Symfony\Component\Security\Core\Authorization\Voter\Voter;
        class PostVoter extends Voter
        {
            protected function supports(string $attribute, mixed $subject): bool { return 'POST_EDIT' === $attribute; }
        }
        PHP;

    public const string GUARDED_CONTROLLER = <<<'PHP'
        <?php
        namespace App\Controller;
        use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
        use Symfony\Component\Routing\Attribute\Route;
        use Symfony\Component\Security\Http\Attribute\IsGranted;
        class PostController extends AbstractController
        {
            #[Route('/post/{id}/edit')]
            #[IsGranted('POST_EDIT')]
            public function edit() { return 1; }
        }
        PHP;

    public const string UNRELATED_CONTROLLER = <<<'PHP'
        <?php
        namespace App\Controller;
        use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
        use Symfony\Component\Routing\Attribute\Route;
        class HomeController extends AbstractController
        {
            #[Route('/')]
            public function index() { return 1; }
        }
        PHP;

    /**
     * @return list<ProjectFile>
     *
     * @throws InvalidProjectFileException
     */
    public static function files(): array
    {
        return [
            ProjectFile::create('src/Controller/HomeController.php', '/project/src/Controller/HomeController.php', self::UNRELATED_CONTROLLER),
            ProjectFile::create('src/Controller/PostController.php', '/project/src/Controller/PostController.php', self::GUARDED_CONTROLLER),
            ProjectFile::create('src/Security/PostVoter.php', '/project/src/Security/PostVoter.php', self::VOTER),
        ];
    }

    public static function preview(string $sinceClosure): SinceClosurePreview
    {
        return new SinceClosurePreview(
            new MappingStage(new NullLogger(), new PhpParserControllerAccessControlParser(), new PhpParserVoterCapabilityParser(), new PhpParserFormBindingParser(), new SymfonyYamlSecurityConfigParser(new NullLogger())),
            new DependencyExpansionStage(new NullLogger(), $sinceClosure),
        );
    }
}
