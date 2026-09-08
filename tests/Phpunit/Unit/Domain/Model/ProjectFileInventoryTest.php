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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\SymfonyProjectFile;

final class ProjectFileInventoryTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('knownComponentTypeCases')]
    public function test_from_files_counts_a_file_of_a_known_component_type_that_is_not_one_of_the_six_explicit_buckets(string $path, string $content): void
    {
        $projectFile = SymfonyProjectFile::create($path, '/app/'.$path, $content);

        $projectFileInventory = ProjectFileInventory::fromFiles([$projectFile]);

        self::assertSame(1, $projectFileInventory->totalFiles());
    }

    /** @return iterable<string, array{string, string}> */
    public static function knownComponentTypeCases(): iterable
    {
        yield 'authenticator' => ['src/Security/LoginAuthenticator.php', '<?php class LoginAuthenticator {}'];
        yield 'messenger handler' => ['src/Messenger/SendInvoiceMessageHandler.php', '<?php class SendInvoiceMessageHandler {}'];
        yield 'event subscriber' => ['src/EventSubscriber/AuditSubscriber.php', '<?php class AuditSubscriber {}'];
        yield 'normalizer' => ['src/Serializer/UserNormalizer.php', '<?php class UserNormalizer {}'];
        yield 'webhook consumer' => ['src/Webhook/StripeWebhookConsumer.php', '<?php class StripeWebhookConsumer {}'];
        yield 'scheduler' => ['src/Schedule/CleanupSchedule.php', '<?php class CleanupSchedule {}'];
        yield 'twig extension' => ['src/Twig/AppExtension.php', "<?php\nclass AppExtension implements ExtensionInterface {}"];
        yield 'api resource' => ['src/ApiResource/Offer.php', "<?php\n#[ApiResource]\nclass Offer {}"];
        yield 'live component' => ['src/Twig/Components/SearchBar.php', "<?php\n#[AsLiveComponent]\nclass SearchBar {}"];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_from_files_puts_every_php_file_in_exactly_one_bucket(): void
    {
        $projectFile = SymfonyProjectFile::create('src/Controller/UserController.php', '/app/x', '<?php class UserController {}');
        $entity = SymfonyProjectFile::create('src/Entity/User.php', '/app/x', '<?php class User {}');
        $authenticator = SymfonyProjectFile::create('src/Security/LoginAuthenticator.php', '/app/x', '<?php class LoginAuthenticator {}');

        $projectFileInventory = ProjectFileInventory::fromFiles([$projectFile, $entity, $authenticator]);

        self::assertSame(3, $projectFileInventory->totalFiles());
        self::assertCount(1, $projectFileInventory->entrypoints());
        self::assertCount(1, $projectFileInventory->domainModels());
        self::assertCount(1, $projectFileInventory->services());
    }

    /**
     * @param Closure(ProjectFileInventory): list<ProjectFile> $bucket
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('sameArchetypeCases')]
    public function test_a_bucket_holds_every_file_of_its_archetype_not_just_the_one_named_type(
        Closure $bucket,
        string $path,
        string $content,
    ): void {
        $projectFileInventory = ProjectFileInventory::fromFiles([
            SymfonyProjectFile::create($path, '/app/'.$path, $content),
        ]);

        self::assertCount(1, $bucket($projectFileInventory));
        self::assertCount(0, $projectFileInventory->services());
    }

    /** @return iterable<string, array{Closure(ProjectFileInventory): list<ProjectFile>, string, string}> */
    public static function sameArchetypeCases(): iterable
    {
        $entrypoints = static fn (ProjectFileInventory $projectFileInventory): array => $projectFileInventory->entrypoints();

        yield 'api resource is an entrypoint' => [$entrypoints, 'src/ApiResource/Offer.php', "<?php\n#[ApiResource]\nclass Offer {}"];
        yield 'live component is an entrypoint' => [$entrypoints, 'src/Twig/Components/SearchBar.php', "<?php\n#[AsLiveComponent]\nclass SearchBar {}"];
        yield 'easyadmin crud is an entrypoint' => [$entrypoints, 'src/Controller/Admin/UserCrudController.php', "<?php\nclass UserCrudController extends AbstractCrudController {}"];
        yield 'sonata admin is an input binding' => [
            static fn (ProjectFileInventory $projectFileInventory): array => $projectFileInventory->inputBindings(),
            'src/Admin/StoreAdmin.php',
            "<?php\nclass StoreAdmin extends AbstractAdmin {}",
        ];
        yield 'twig extension is a template surface' => [
            static fn (ProjectFileInventory $projectFileInventory): array => $projectFileInventory->templates(),
            'src/Twig/AppExtension.php',
            "<?php\nclass AppExtension implements ExtensionInterface {}",
        ];
    }
}
