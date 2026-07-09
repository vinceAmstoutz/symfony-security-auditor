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

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;

final class PhpParserVoterCapabilityParserTest extends TestCase
{
    private PhpParserVoterCapabilityParser $phpParserVoterCapabilityParser;

    #[Override]
    protected function setUp(): void
    {
        $this->phpParserVoterCapabilityParser = new PhpParserVoterCapabilityParser();
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_for_non_voter_file(): void
    {
        $projectFile = ProjectFile::create('src/Service/Mailer.php', '/app/x', '<?php class Mailer {}');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_for_non_voter_file_even_when_it_defines_a_supports_method(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Service;
            final class Helper {
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, ['CAN_HELP'], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Service/Helper.php', '/app/x', $source);

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_for_unparseable_voter(): void
    {
        $projectFile = ProjectFile::create('src/Security/BrokenVoter.php', '/app/x', '<?php class BrokenVoter { public function');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_when_voter_file_declares_no_class(): void
    {
        $projectFile = ProjectFile::create('src/Security/HelperVoter.php', '/app/x', '<?php function supports(): bool { return true; }');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_when_voter_has_no_supports_method(): void
    {
        $projectFile = ProjectFile::create('src/Security/BareVoter.php', '/app/x', '<?php class BareVoter { public function hello(): void {} }');

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_when_supports_is_abstract_without_a_body(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            abstract class AbstractVoter {
                abstract public function supports(string $attribute, mixed $subject): bool;
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/AbstractVoter.php', '/app/x', $source);

        self::assertNull($this->phpParserVoterCapabilityParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_empty_string_literals_in_supports_body(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class EmptyAttrVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, ['', 'EDIT'], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/EmptyAttrVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['EDIT'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_instanceof_against_a_dynamic_class_expression(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Post;
            final class DynamicSubjectVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    $class = Post::class;
                    return $subject instanceof $class || $subject instanceof Post;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/DynamicSubjectVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['App\\Entity\\Post'], $voterCapability->supportedSubjects());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_empty_class_name_for_an_anonymous_voter_class(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            $voter = new class {
                public function supports(string $attribute, mixed $subject): bool {
                    return $attribute === 'VIEW';
                }
            };
            PHP;
        $projectFile = ProjectFile::create('src/Security/AnonymousVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame('', $voterCapability->className());
        self::assertSame(['VIEW'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_extracts_attributes_checked_inside_a_private_helper_called_from_supports(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Post;
            final class PostVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return $this->isSupportedAttribute($attribute) && $subject instanceof Post;
                }
                private function isSupportedAttribute(string $attribute): bool {
                    return in_array($attribute, ['EDIT', 'DELETE'], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['EDIT', 'DELETE'], $voterCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\Post'], $voterCapability->supportedSubjects());
    }

    /**
     * The abstract Symfony `Voter` class's canonical style checks only the
     * subject type in `supports()` and dispatches on the attribute inside
     * `voteOnAttribute()` — this attribute vocabulary must not be invisible
     * to the "Voter Coverage" prompt block just because it lives in a
     * different method than `supports()`.
     *
     * @throws InvalidProjectFileException
     */
    public function test_it_extracts_attributes_from_vote_on_attribute_when_supports_only_checks_the_subject_type(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Post;
            use Symfony\Component\Security\Core\Authorization\Voter\Voter;
            use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
            final class PostVoter extends Voter {
                protected function supports(string $attribute, mixed $subject): bool {
                    return $subject instanceof Post;
                }
                protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool {
                    return match ($attribute) {
                        'EDIT' => true,
                        'VIEW' => true,
                        default => false,
                    };
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['EDIT', 'VIEW'], $voterCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\Post'], $voterCapability->supportedSubjects());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_does_not_infinitely_recurse_when_private_helpers_call_each_other_in_a_cycle(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class PostVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return $this->helperOne($attribute);
                }
                private function helperOne(string $attribute): bool {
                    return $this->helperTwo($attribute);
                }
                private function helperTwo(string $attribute): bool {
                    return $this->helperOne($attribute);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame([], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_finds_the_voter_class_when_it_is_not_the_first_class_declared_in_the_file(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Post;
            final class PostVoterAttributes {
                public const string EDIT = 'EDIT';
            }
            final class PostVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, ['EDIT', 'DELETE'], true) && $subject instanceof Post;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame('App\\Security\\PostVoter', $voterCapability->className());
        self::assertSame(['EDIT', 'DELETE'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_extracts_capabilities_from_a_voter_implementing_voter_interface_directly(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\ApiKey;
            use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
            final class ApiScopeVoter implements VoterInterface {
                public function vote(mixed $token, mixed $subject, array $attributes): int {
                    foreach ($attributes as $attribute) {
                        if ('SCOPE_READ' === $attribute) {
                            return $subject instanceof ApiKey ? self::ACCESS_GRANTED : self::ACCESS_DENIED;
                        }
                    }
                    return self::ACCESS_ABSTAIN;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/ApiScopeVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['SCOPE_READ'], $voterCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\ApiKey'], $voterCapability->supportedSubjects());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_collects_multiple_subject_types_from_supports_body(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\User;
            use App\Entity\Comment;
            final class CrossVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return $subject instanceof User || $subject instanceof Comment;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/CrossVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['App\\Entity\\User', 'App\\Entity\\Comment'], $voterCapability->supportedSubjects());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_deduplicates_repeated_subject_type_in_supports_body_and_continues_to_collect_later_unique_types(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\User;
            use App\Entity\Comment;
            final class MixedVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return $subject instanceof User
                        || $subject instanceof User
                        || $subject instanceof Comment;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/MixedVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['App\\Entity\\User', 'App\\Entity\\Comment'], $voterCapability->supportedSubjects());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_deduplicates_repeated_string_literal_in_supports_body_and_continues_to_collect_later_unique_attributes(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class RepeatAttrVoter {
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, ['EDIT', 'EDIT', 'DELETE'], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/RepeatAttrVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['EDIT', 'DELETE'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_resolves_self_and_static_class_constant_fetches_to_their_string_values(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Post;
            final class PostVoter {
                const EDIT = 'edit';
                const VIEW = 'view';
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, [self::EDIT, static::VIEW], true) && $subject instanceof Post;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['edit', 'view'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_resolves_a_self_constant_fetch_naming_an_array_of_string_attributes(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            use App\Entity\Post;
            final class PostVoter {
                private const array SUPPORTED_ATTRIBUTES = ['edit', 'view', 'delete'];
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, self::SUPPORTED_ATTRIBUTES, true) && $subject instanceof Post;
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/PostVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['edit', 'view', 'delete'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_a_dynamic_constant_fetch(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class DynamicConstVoter {
                const EDIT = 'edit';
                public function supports(string $attribute, mixed $subject): bool {
                    $name = $attribute;
                    return in_array($attribute, [self::{$name}], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/DynamicConstVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame([], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_a_constant_fetch_on_a_variable_class_expression(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class VariableClassConstVoter {
                const EDIT = 'edit';
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, [$subject::EDIT], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/VariableClassConstVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame([], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_deduplicates_two_own_constants_that_share_the_same_string_value(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class AliasedConstVoter {
                const EDIT = 'edit';
                const ALIAS = 'edit';
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, [self::EDIT, self::ALIAS], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/AliasedConstVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['edit'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_does_not_duplicate_a_value_reachable_as_both_a_literal_and_a_constant_fetch(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class MixedAttrVoter {
                const EDIT = 'EDIT';
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, ['EDIT', self::EDIT, 'DELETE'], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/MixedAttrVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame(['EDIT', 'DELETE'], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_a_constant_fetch_that_does_not_resolve_to_an_own_string_constant(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Security;
            final class UnresolvedConstVoter {
                const LIMIT = 5;
                public function supports(string $attribute, mixed $subject): bool {
                    return in_array($attribute, [self::LIMIT, self::MISSING, parent::SHARED], true);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Security/UnresolvedConstVoter.php', '/app/x', $source);

        $voterCapability = $this->phpParserVoterCapabilityParser->parse($projectFile);

        self::assertNotNull($voterCapability);
        self::assertSame([], $voterCapability->supportedAttributes());
    }

    /**
     * @throws InvalidProjectFileException
     */
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
