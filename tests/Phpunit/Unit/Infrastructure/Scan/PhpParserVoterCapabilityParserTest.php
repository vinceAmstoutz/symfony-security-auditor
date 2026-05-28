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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;

final class PhpParserVoterCapabilityParserTest extends TestCase
{
    private PhpParserVoterCapabilityParser $phpParserVoterCapabilityParser;

    protected function setUp(): void
    {
        $this->phpParserVoterCapabilityParser = new PhpParserVoterCapabilityParser();
    }

    public function test_it_returns_null_for_non_voter_file(): void
    {
        $projectFile = ProjectFile::create('src/Service/Mailer.php', '/app/x', '<?php class Mailer {}');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    public function test_it_returns_null_for_unparseable_voter(): void
    {
        $projectFile = ProjectFile::create('src/Security/Broken.php', '/app/x', '<?php class Broken { public function');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    public function test_it_returns_null_when_voter_has_no_supports_method(): void
    {
        $projectFile = ProjectFile::create('src/Security/Bare.php', '/app/x', '<?php class Bare { public function hello(): void {} }');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    public function test_it_extracts_attributes_from_in_array_call(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\User;
            final class UserVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, ['EDIT', 'DELETE'], true) && $subject instanceof User;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/UserVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['EDIT', 'DELETE'], $voterCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\User'], $voterCapability->supportedSubjects());
    }

    public function test_it_extracts_attributes_from_match_arms(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Comment;
            final class CommentVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return match ($attribute) {
                        'VIEW', 'EDIT' => $subject instanceof Comment,
                        default => false,
                    };
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/CommentVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['VIEW', 'EDIT'], $voterCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\Comment'], $voterCapability->supportedSubjects());
    }

    public function test_it_extracts_class_name_with_namespace(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class PostVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return $attribute === 'EDIT';
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame('App\\Security\\PostVoter', $voterCapability->className());
        self::assertSame(['EDIT'], $voterCapability->supportedAttributes());
    }
}
