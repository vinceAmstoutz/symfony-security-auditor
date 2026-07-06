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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileTypeClassifier;

final class ProjectFileTypeClassifierTest extends TestCase
{
    #[DataProvider('classificationCases')]
    public function test_it_classifies_a_path_and_content_pair(string $path, string $content, ProjectFileType $projectFileType): void
    {
        self::assertSame($projectFileType, ProjectFileTypeClassifier::classify($path, $content));
    }

    /** @return iterable<string, array{string, string, ProjectFileType}> */
    public static function classificationCases(): iterable
    {
        yield 'controller by directory' => ['src/Controller/UserController.php', '<?php', ProjectFileType::CONTROLLER];
        yield 'api resource by attribute' => ['src/ApiResource/Offer.php', "<?php\n#[ApiResource]\nclass Offer {}", ProjectFileType::API_RESOURCE];
        yield 'live component by attribute' => ['src/Twig/Components/SearchBar.php', "<?php\n#[AsLiveComponent]\nclass SearchBar {}", ProjectFileType::LIVE_COMPONENT];
        yield 'live component extending abstract controller stays a live component' => ['src/Twig/Components/Cart.php', "<?php\n#[AsLiveComponent]\nclass Cart extends AbstractController {}", ProjectFileType::LIVE_COMPONENT];
        yield 'api resource with route attribute stays an api resource' => ['src/ApiResource/Offer.php', "<?php\n#[ApiResource]\n#[Route('/offers')]\nclass Offer {}", ProjectFileType::API_RESOURCE];
        yield 'controller directory wins over api resource attribute' => ['src/Controller/OfferController.php', "<?php\n#[ApiResource]\nclass OfferController {}", ProjectFileType::CONTROLLER];
        yield 'invokable as-controller service without base class or route attribute' => ['src/Action/CheckoutAction.php', "<?php\n#[AsController]\nclass CheckoutAction { public function __invoke() {} }", ProjectFileType::CONTROLLER];
        yield 'controller by route attribute without base class' => ['src/Action/ExportAction.php', "<?php\nclass ExportAction { #[Route('/export')]\npublic function __invoke() {} }", ProjectFileType::CONTROLLER];
        yield 'entity by directory' => ['src/Entity/User.php', '<?php', ProjectFileType::ENTITY];
        yield 'voter by suffix' => ['src/Security/UserVoter.php', '<?php', ProjectFileType::VOTER];
        yield 'repository by directory' => ['src/Repository/UserRepository.php', '<?php', ProjectFileType::REPOSITORY];
        yield 'form by directory and suffix' => ['src/Form/UserType.php', '<?php', ProjectFileType::FORM];
        yield 'authenticator by suffix' => ['src/Security/LoginFormAuthenticator.php', '<?php', ProjectFileType::AUTHENTICATOR];
        yield 'messenger handler by suffix' => ['src/Messenger/SendInvoiceMessageHandler.php', '<?php', ProjectFileType::MESSENGER_HANDLER];
        yield 'webhook consumer by suffix' => ['src/Webhook/StripeWebhookConsumer.php', '<?php', ProjectFileType::WEBHOOK_CONSUMER];
        yield 'event subscriber by suffix' => ['src/EventSubscriber/AuditSubscriber.php', '<?php', ProjectFileType::EVENT_SUBSCRIBER];
        yield 'normalizer by suffix' => ['src/Serializer/UserNormalizer.php', '<?php', ProjectFileType::NORMALIZER];
        yield 'scheduler by suffix' => ['src/Schedule/CleanupSchedule.php', '<?php', ProjectFileType::SCHEDULER];
        yield 'template by extension' => ['templates/user/index.html.twig', '{{ user.name }}', ProjectFileType::TEMPLATE];
        yield 'config by yaml extension' => ['config/security.yaml', 'security:', ProjectFileType::CONFIG];
        yield 'config by xml extension' => ['config/services.xml', '', ProjectFileType::CONFIG];
        yield 'config by dotenv path' => ['.env', 'APP_ENV=prod', ProjectFileType::CONFIG];
        yield 'plain php falls back to php' => ['src/Service/FooService.php', '<?php', ProjectFileType::PHP];
        yield 'unrecognized path falls back to other' => ['README.md', '# Docs', ProjectFileType::OTHER];
    }

    public function test_a_non_php_file_in_a_webhook_directory_is_not_forced_into_webhook_consumer(): void
    {
        $projectFileType = ProjectFileTypeClassifier::classify('src/Webhook/config.yaml', 'foo: bar');

        self::assertSame(ProjectFileType::CONFIG, $projectFileType);
    }

    public function test_a_non_php_file_in_a_message_handler_directory_is_not_forced_into_messenger_handler(): void
    {
        $projectFileType = ProjectFileTypeClassifier::classify('src/MessageHandler/config.yaml', 'foo: bar');

        self::assertSame(ProjectFileType::CONFIG, $projectFileType);
    }
}
