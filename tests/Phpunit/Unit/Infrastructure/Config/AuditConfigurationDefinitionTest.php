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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;

final class AuditConfigurationDefinitionTest extends TestCase
{
    private const array RISK_PATTERNS = ['audit_log' => ['regex' => '/AuditService::log/', 'description' => 'privileged action logged']];

    private const string ENV_PLACEHOLDER = 'env_0123456789abcdef_MODEL_0123456789abcdef0123456789abcdef';

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeys')]
    public function test_an_explicit_null_on_a_nullable_numeric_key_is_accepted_as_null(array $path): void
    {
        $processed = $this->process([self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeysWithANumber')]
    public function test_an_explicit_null_resets_a_value_set_by_an_earlier_configuration(array $path, int|float $number): void
    {
        $processed = $this->process([self::nested($path, $number), self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeysWithANumber')]
    public function test_a_nullable_numeric_key_still_reads_a_number(array $path, int|float $number): void
    {
        $processed = $this->process([self::nested($path, $number)]);

        self::assertSame($number, $this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeysWithAValueBelowTheirMinimum')]
    public function test_a_nullable_numeric_key_still_refuses_a_value_below_its_minimum(array $path, int|float $belowMinimum): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([self::nested($path, $belowMinimum)]);
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeys')]
    public function test_a_nullable_numeric_key_still_refuses_a_value_that_is_no_number(array $path): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([self::nested($path, 'many')]);
    }

    public function test_min_score_accepts_one_hundred(): void
    {
        $processed = $this->process([['audit' => ['min_score' => 100]]]);

        self::assertSame(100, $this->valueAt($processed, ['audit', 'min_score']));
    }

    public function test_min_score_refuses_a_value_above_one_hundred(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([['audit' => ['min_score' => 101]]]);
    }

    public function test_the_gitignore_is_respected_and_the_tracked_ignored_files_are_left_out_by_default(): void
    {
        $processed = $this->process([[]]);

        self::assertTrue($this->valueAt($processed, ['scan', 'respect_gitignore']));
        self::assertFalse($this->valueAt($processed, ['scan', 'include_tracked_ignored']));
    }

    public function test_the_tracked_ignored_files_opt_in_reads_true(): void
    {
        $processed = $this->process([['scan' => ['include_tracked_ignored' => true]]]);

        self::assertTrue($this->valueAt($processed, ['scan', 'include_tracked_ignored']));
    }

    public function test_the_tracked_ignored_files_opt_in_refuses_a_value_that_is_no_boolean(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([['scan' => ['include_tracked_ignored' => 'yes']]]);
    }

    public function test_dot_files_are_left_out_of_the_scan_by_default(): void
    {
        self::assertFalse($this->valueAt($this->process([[]]), ['scan', 'include_dotfiles']));
    }

    public function test_the_dot_files_opt_in_reads_true(): void
    {
        $processed = $this->process([['scan' => ['include_dotfiles' => true]]]);

        self::assertTrue($this->valueAt($processed, ['scan', 'include_dotfiles']));
    }

    public function test_the_dot_files_opt_in_refuses_a_value_that_is_no_boolean(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([['scan' => ['include_dotfiles' => 'yes']]]);
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function nullableNumericKeys(): iterable
    {
        foreach (self::keysWithTheirNumbers() as $name => [$path]) {
            yield $name => [$path];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, int|float}>
     */
    public static function nullableNumericKeysWithANumber(): iterable
    {
        foreach (self::keysWithTheirNumbers() as $name => [$path, $number]) {
            yield $name => [$path, $number];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, int|float}>
     */
    public static function nullableNumericKeysWithAValueBelowTheirMinimum(): iterable
    {
        foreach (self::keysWithTheirNumbers() as $name => [$path, , $belowMinimum]) {
            yield $name => [$path, $belowMinimum];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, int|float, int|float}>
     */
    private static function keysWithTheirNumbers(): iterable
    {
        yield 'attacker_max_output_tokens' => [['attacker_max_output_tokens'], 8, 0];
        yield 'reviewer_max_output_tokens' => [['reviewer_max_output_tokens'], 8, 0];
        yield 'audit.max_iterations' => [['audit', 'max_iterations'], 8, 0];
        yield 'audit.attacker_max_concurrent' => [['audit', 'attacker_max_concurrent'], 8, 0];
        yield 'audit.reviewer_max_concurrent' => [['audit', 'reviewer_max_concurrent'], 8, 0];
        yield 'audit.min_score' => [['audit', 'min_score'], 80, -1];
        yield 'audit.budget.max_tokens' => [['audit', 'budget', 'max_tokens'], 8, 0];
        yield 'audit.budget.max_cost_usd' => [['audit', 'budget', 'max_cost_usd'], 8.5, 0.0];
        yield 'audit.rate_limit.requests_per_minute' => [['audit', 'rate_limit', 'requests_per_minute'], 8, 0];
        yield 'audit.rate_limit.input_tokens_per_minute' => [['audit', 'rate_limit', 'input_tokens_per_minute'], 8, 0];
        yield 'audit.rate_limit.output_tokens_per_minute' => [['audit', 'rate_limit', 'output_tokens_per_minute'], 8, 0];
    }

    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_a_risk_pattern_bucket_that_names_no_file_type_is_kept_and_deprecated(): void
    {
        $this->expectUserDeprecationMessage('Since vinceamstoutz/symfony-security-auditor 1.22: scan.custom_risk_patterns.controlers names no file type, so its patterns never run. Key them by one of: controller, api_resource, live_component, entity, voter, repository, form, authenticator, ldap_service, sonata_admin, easyadmin_crud, messenger_handler, webhook_consumer, event_subscriber, normalizer, scheduler, twig_extension, template, config, php, other. A bucket that names no file type is deprecated and will be refused in 2.0.');

        $processed = $this->process([['scan' => ['custom_risk_patterns' => ['controller' => self::RISK_PATTERNS, 'controlers' => self::RISK_PATTERNS]]]]);

        self::assertSame(['controller' => self::RISK_PATTERNS, 'controlers' => self::RISK_PATTERNS], $this->valueAt($processed, ['scan', 'custom_risk_patterns']));
    }

    public function test_risk_pattern_buckets_that_each_name_a_file_type_are_kept(): void
    {
        $processed = $this->process([['scan' => ['custom_risk_patterns' => ['controller' => self::RISK_PATTERNS, 'php' => self::RISK_PATTERNS]]]]);

        self::assertSame(['controller' => self::RISK_PATTERNS, 'php' => self::RISK_PATTERNS], $this->valueAt($processed, ['scan', 'custom_risk_patterns']));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('valuesThatAreNoTextOnAModelKey')]
    public function test_a_model_key_refuses_a_value_that_is_no_text(array $path, mixed $value, string $type): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Invalid type for path "symfony_security_auditor.%s". Expected "string", but got "%s".', implode('.', $path), $type));

        $this->process([self::nested($path, $value)]);
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, mixed, string}>
     */
    public static function valuesThatAreNoTextOnAModelKey(): iterable
    {
        foreach (self::modelKeys() as $name => [$path]) {
            yield $name.' set to a number' => [$path, 5, 'int'];
            yield $name.' set to a decimal' => [$path, 4.1, 'float'];
            yield $name.' set to a switch' => [$path, true, 'bool'];
        }
    }

    /**
     * @param non-empty-list<string> $path
     * @param array<string, mixed>   $siblings
     */
    #[DataProvider('valuesThatAreNoTextOnATextKey')]
    public function test_a_text_key_refuses_a_value_that_is_no_text(array $path, array $siblings, mixed $value, string $type): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Invalid type for path "symfony_security_auditor.%s". Expected "string", but got "%s".', implode('.', $path), $type));

        $this->process([$this->textSetting($path, $siblings, $value)]);
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, array<string, mixed>, mixed, string}>
     */
    public static function valuesThatAreNoTextOnATextKey(): iterable
    {
        foreach (self::textKeys() as $name => [$path, $siblings]) {
            yield $name.' set to a number' => [$path, $siblings, 5, 'int'];
            yield $name.' set to a decimal' => [$path, $siblings, 4.1, 'float'];
            yield $name.' set to a switch' => [$path, $siblings, false, 'bool'];
        }

        yield 'cache.dir set to null' => [['cache', 'dir'], [], null, 'null'];
    }

    /**
     * @param non-empty-list<string> $path
     * @param array<string, mixed>   $siblings
     */
    #[DataProvider('textKeys')]
    public function test_a_text_key_still_reads_text(array $path, array $siblings): void
    {
        $processed = $this->process([$this->textSetting($path, $siblings, 'var/audit')]);

        self::assertSame('var/audit', $this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     * @param array<string, mixed>   $siblings
     */
    #[DataProvider('textKeys')]
    public function test_a_text_key_set_to_a_list_keeps_the_message_it_had(array $path, array $siblings): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Invalid type for path "symfony_security_auditor.%s". Expected "scalar", but got "array".', implode('.', $path)));

        $this->process([$this->textSetting($path, $siblings, ['var/audit'])]);
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('textKeysTakingAnEmptyString')]
    public function test_a_text_key_still_takes_an_empty_string(array $path): void
    {
        $processed = $this->process([self::nested($path, '')]);

        self::assertSame('', $this->valueAt($processed, $path));
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function textKeysTakingAnEmptyString(): iterable
    {
        yield 'cache.dir' => [['cache', 'dir']];
        yield from self::optionalTextKeys();
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('optionalTextKeys')]
    public function test_an_explicit_null_on_an_optional_text_key_resets_the_value_an_earlier_configuration_set(array $path): void
    {
        $processed = $this->process([self::nested($path, 'var/audit'), self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function optionalTextKeys(): iterable
    {
        yield 'audit.baseline' => [['audit', 'baseline']];
        yield 'audit.output' => [['audit', 'output']];
        yield 'audit.report_path_prefix' => [['audit', 'report_path_prefix']];
    }

    public function test_the_instructions_of_a_custom_skill_set_to_null_keep_the_message_they_had(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The path "symfony_security_auditor.audit.custom_skills.pricing.instructions" cannot contain an empty value, but got null.');

        $this->process([['audit' => ['custom_skills' => ['pricing' => ['file_type' => 'controller', 'instructions' => null]]]]]);
    }

    /**
     * @param non-empty-list<string> $path
     * @param array<string, mixed>   $siblings
     * @param array<string, mixed>   $standIns
     */
    #[DataProvider('envPlaceholderStandInsOnATextKey')]
    public function test_a_text_key_takes_an_env_placeholder_whatever_stand_in_symfony_checks_it_with(array $path, array $siblings, array $standIns): void
    {
        BaseNode::setPlaceholder(self::ENV_PLACEHOLDER, $standIns);

        $processed = $this->process([$this->textSetting($path, $siblings, self::ENV_PLACEHOLDER)]);

        self::assertSame(self::ENV_PLACEHOLDER, $this->valueAt($processed, $path));
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, array<string, mixed>, array<string, mixed>}>
     */
    public static function envPlaceholderStandInsOnATextKey(): iterable
    {
        foreach (self::textKeys() as $name => [$path, $siblings]) {
            yield $name.' read through a variable with no default' => [$path, $siblings, ['string' => '']];
            yield $name.' read through a variable whose default is null' => [$path, $siblings, ['string' => null]];
            yield $name.' read through a typed processor' => [$path, $siblings, ['int' => 0]];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, array<string, mixed>}>
     */
    public static function textKeys(): iterable
    {
        yield 'cache.dir' => [['cache', 'dir'], []];
        yield 'audit.baseline' => [['audit', 'baseline'], []];
        yield 'audit.output' => [['audit', 'output'], []];
        yield 'audit.report_path_prefix' => [['audit', 'report_path_prefix'], []];
        yield 'the instructions of a custom skill' => [['audit', 'custom_skills', 'pricing', 'instructions'], ['file_type' => 'controller']];
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('modelKeys')]
    public function test_a_model_key_still_reads_a_model_name(array $path): void
    {
        $processed = $this->process([self::nested($path, 'gpt-4o')]);

        self::assertSame('gpt-4o', $this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('modelOverrideKeys')]
    public function test_an_explicit_null_on_a_model_override_resets_the_model_an_earlier_configuration_set(array $path): void
    {
        $processed = $this->process([self::nested($path, 'gpt-4o'), self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     * @param array<string, mixed>   $standIns
     */
    #[DataProvider('envPlaceholderStandInsOnAModelKey')]
    public function test_a_model_key_takes_an_env_placeholder_whatever_stand_in_symfony_checks_it_with(array $path, array $standIns): void
    {
        BaseNode::setPlaceholder(self::ENV_PLACEHOLDER, $standIns);

        $processed = $this->process([self::nested($path, self::ENV_PLACEHOLDER)]);

        self::assertSame(self::ENV_PLACEHOLDER, $this->valueAt($processed, $path));
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, array<string, mixed>}>
     */
    public static function envPlaceholderStandInsOnAModelKey(): iterable
    {
        foreach (self::modelKeys() as $name => [$path]) {
            yield $name.' read through a variable with no default' => [$path, ['string' => '']];
            yield $name.' read through a variable whose default is null' => [$path, ['string' => null]];
            yield $name.' read through a typed processor' => [$path, ['int' => 0]];
        }
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('modelKeys')]
    public function test_a_model_key_set_to_a_list_keeps_the_message_it_had(array $path): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Invalid type for path "symfony_security_auditor.%s". Expected "scalar", but got "array".', implode('.', $path)));

        $this->process([self::nested($path, ['gpt-4o'])]);
    }

    #[DataProvider('emptyModels')]
    public function test_an_empty_model_keeps_the_message_it_had(?string $model, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->process([['model' => $model]]);
    }

    /**
     * @return iterable<string, array{?string, string}>
     */
    public static function emptyModels(): iterable
    {
        yield 'an empty string' => ['', 'The path "symfony_security_auditor.model" cannot contain an empty value, but got "".'];
        yield 'null' => [null, 'The path "symfony_security_auditor.model" cannot contain an empty value, but got null.'];
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function modelKeys(): iterable
    {
        yield 'model' => [['model']];
        yield from self::modelOverrideKeys();
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function modelOverrideKeys(): iterable
    {
        yield 'attacker_model' => [['attacker_model']];
        yield 'reviewer_model' => [['reviewer_model']];
        yield 'audit.escalation.cheap_model' => [['audit', 'escalation', 'cheap_model']];
    }

    #[Override]
    protected function tearDown(): void
    {
        BaseNode::resetPlaceholders();
    }

    /**
     * @param list<array<array-key, mixed>> $configs
     *
     * @return array<array-key, mixed>
     */
    private function process(array $configs): array
    {
        $treeBuilder = new TreeBuilder('symfony_security_auditor');
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());

        return (new Processor())->process($treeBuilder->buildTree(), $configs);
    }

    /**
     * @param non-empty-list<string> $path
     *
     * @return array<array-key, mixed>
     */
    private static function nested(array $path, mixed $value): array
    {
        $key = array_shift($path);

        return [$key => [] === $path ? $value : self::nested($path, $value)];
    }

    /**
     * @param non-empty-list<string> $path
     * @param array<string, mixed>   $siblings the keys the text key's parent requires beside it
     *
     * @return array<array-key, mixed>
     */
    private function textSetting(array $path, array $siblings, mixed $value): array
    {
        $key = array_pop($path);
        $parent = $siblings + [$key => $value];

        return [] === $path ? $parent : self::nested($path, $parent);
    }

    /**
     * @param array<array-key, mixed> $config
     * @param list<string>            $path
     */
    private function valueAt(array $config, array $path): mixed
    {
        $value = $config;

        foreach ($path as $key) {
            self::assertIsArray($value);
            $value = $value[$key];
        }

        return $value;
    }
}
