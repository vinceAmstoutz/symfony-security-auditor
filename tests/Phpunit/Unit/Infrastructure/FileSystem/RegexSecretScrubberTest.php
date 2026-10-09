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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem;

use Override;
use PDO;
use PhpParser\ParserFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;

final class RegexSecretScrubberTest extends TestCase
{
    // Credential-shaped prefixes split as constants so GitHub's secret scanner does not flag the source.
    private const string AWS = 'AKIA';

    private const string GHP = 'ghp';

    private const string GHO = 'gho';

    private const string GITHUB_PAT = 'github_pat';

    private const string STRIPE_LIVE = 'sk_live';

    private const string STRIPE_RK = 'rk_test';

    private const string GOOGLE = 'AIza';

    private const string JWT = 'eyJ';

    private const string OPENAI_SK = 'sk-proj';

    private const string GITLAB_PAT = 'glpat';

    private const string HUGGING_FACE = 'hf';

    private const string NPM = 'npm';

    private const string SENDGRID = 'SG';

    private const string PYPI = 'pypi';

    private const string DISCORD_WEBHOOKS = 'https://discord.com/api/webhooks';

    private RegexSecretScrubber $regexSecretScrubber;

    #[DataProvider('credentialPatternCases')]
    public function test_it_redacts_credential_shaped_strings(string $input, string $expectedFragment): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertStringNotContainsString($this->secretFragmentOf($input), $output);
        self::assertStringContainsString($expectedFragment, $output);
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function credentialPatternCases(): iterable
    {
        yield 'aws_access_key' => [
            self::AWS.'IOSFODNN7EXAMPLE',
            '***REDACTED:aws_access_key***',
        ];
        yield 'github_personal_access_token' => [
            self::GHP.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
            '***REDACTED:github_token***',
        ];
        yield 'github_oauth_token' => [
            self::GHO.'_1234567890abcdefghijklmnopqrstuvwxyz',
            '***REDACTED:github_token***',
        ];
        yield 'github_fine_grained_pat' => [
            self::GITHUB_PAT.'_11AABBCCDD0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            '***REDACTED:github_token***',
        ];
        yield 'stripe_live_key' => [
            self::STRIPE_LIVE.'_4eC39HqLyjWDarjtT1zdp7dc',
            '***REDACTED:stripe_key***',
        ];
        yield 'stripe_test_restricted_key' => [
            self::STRIPE_RK.'_4eC39HqLyjWDarjtT1zdp7dc',
            '***REDACTED:stripe_key***',
        ];
        yield 'slack_bot_token' => [
            'xoxb-1234567890-abcdefghij',
            '***REDACTED:slack_token***',
        ];
        yield 'google_api_key' => [
            self::GOOGLE.'SyA1234567890abcdefghijklmnopqrstuv',
            '***REDACTED:google_api_key***',
        ];
        yield 'jwt_token' => [
            self::JWT.'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            '***REDACTED:jwt***',
        ];
        yield 'pem_private_key' => [
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxYZ\n-----END RSA PRIVATE KEY-----",
            '***REDACTED:pem_private_key***',
        ];
        yield 'env_token_assignment' => [
            'STRIPE_SECRET_KEY=sk_super_secret_value_123',
            '***REDACTED:env_assignment***',
        ];
        yield 'env_password_assignment' => [
            'DATABASE_PASSWORD=hunter2supersecure',
            '***REDACTED:env_assignment***',
        ];
        yield 'env_pass_assignment' => [
            'DB_PASS=hunter2supersecure',
            '***REDACTED:env_assignment***',
        ];
        yield 'env_pw_assignment' => [
            'MYSQL_ROOT_PW=hunter2supersecure',
            '***REDACTED:env_assignment***',
        ];
        yield 'inline_pass_yaml' => [
            "pass: 'supersecretvalue'",
            '***REDACTED:inline_assignment***',
        ];
        yield 'inline_password_yaml' => [
            'password: "supersecretvalue"',
            '***REDACTED:inline_assignment***',
        ];
        yield 'inline_api_key_php_array' => [
            "'api_key' => 'abcdefghij1234567890'",
            '***REDACTED:inline_assignment***',
        ];
        yield 'database_url_connection_string' => [
            'DATABASE_URL=postgres://app_user:s3cr3tValue@db.example.com:5432/app',
            '***REDACTED:connection_uri***',
        ];
        yield 'redis_url_connection_string_without_user' => [
            'REDIS_URL=redis://:s3cr3tValue@localhost:6379',
            '***REDACTED:connection_uri***',
        ];
        yield 'bearer_token_header' => [
            'Bearer '.str_repeat('a1B2', 8),
            '***REDACTED:bearer_token***',
        ];
        yield 'openai_api_key' => [
            self::OPENAI_SK.'-'.str_repeat('a1B2', 10),
            '***REDACTED:openai_api_key***',
        ];
        yield 'basic_authorization_header' => [
            'Authorization: Basic '.base64_encode('admin:s3cr3tValue1'),
            '***REDACTED:basic_authorization***',
        ];
        yield 'basic_authorization_proxy_header' => [
            'Proxy-Authorization: Basic '.base64_encode('admin:s3cr3tValue1'),
            '***REDACTED:basic_authorization***',
        ];
        yield 'basic_authorization_php_array' => [
            "'Authorization' => 'Basic ".base64_encode('admin:s3cr3tValue1')."'",
            '***REDACTED:basic_authorization***',
        ];
        yield 'slack_app_level_token' => [
            'xapp-1-A012345678-1234567890123-'.str_repeat('a1B2', 8),
            '***REDACTED:slack_token***',
        ];
        yield 'slack_incoming_webhook_url' => [
            'https://hooks.slack.com/services/T00000000/B00000000/'.str_repeat('X', 24),
            '***REDACTED:slack_webhook_url***',
        ];
        yield 'gitlab_personal_access_token' => [
            self::GITLAB_PAT.'-'.str_repeat('Ab1', 8),
            '***REDACTED:gitlab_token***',
        ];
        yield 'gitlab_runner_token' => [
            'glrt-'.str_repeat('Ab1', 8),
            '***REDACTED:gitlab_token***',
        ];
        yield 'hugging_face_token' => [
            self::HUGGING_FACE.'_'.str_repeat('Xy9', 12),
            '***REDACTED:huggingface_token***',
        ];
        yield 'npm_granular_token' => [
            self::NPM.'_'.str_repeat('a1B2c3', 6),
            '***REDACTED:npm_token***',
        ];
        yield 'sendgrid_api_key' => [
            self::SENDGRID.'.'.str_repeat('a', 22).'.'.str_repeat('b', 43),
            '***REDACTED:sendgrid_api_key***',
        ];
        yield 'pypi_api_token' => [
            self::PYPI.'-AgEIcHlwaS5vcmc'.str_repeat('A1b2', 20),
            '***REDACTED:pypi_token***',
        ];
        yield 'env_glued_secret_key' => [
            'SECRETKEY=zzz999aaa111',
            'SECRETKEY=***REDACTED:env_assignment***',
        ];
        yield 'env_glued_pg_password' => [
            'PGPASSWORD=hunter2supersecure',
            'PGPASSWORD=***REDACTED:env_assignment***',
        ];
    }

    /**
     * The credential is redacted but the header name and scheme are kept, so the
     * LLM still sees that the request authenticates and how — removing them
     * would hide the auth mechanism the audit is meant to reason about.
     */
    public function test_a_basic_authorization_header_keeps_its_scheme_and_redacts_only_the_credential(): void
    {
        $scrubbed = $this->regexSecretScrubber->scrub('Authorization: Basic '.base64_encode('admin:s3cr3tValue'));

        self::assertSame('Authorization: Basic ***REDACTED:basic_authorization***', $scrubbed);
    }

    /**
     * `basic` and `authorization` are ordinary English words; only the two
     * together, in an assignment, followed by a credential-shaped value, are a
     * secret. Prose that happens to use them must survive untouched.
     */
    public function test_prose_mentioning_basic_authorization_is_not_redacted(): void
    {
        self::assertSame('Use basic authentication over TLS.', $this->regexSecretScrubber->scrub('Use basic authentication over TLS.'));
        self::assertSame('Authorization: required', $this->regexSecretScrubber->scrub('Authorization: required'));
    }

    public function test_an_azure_storage_account_key_is_redacted(): void
    {
        $accountKey = str_repeat('Eby8vdM02xNOcqFctNzYpk', 3).'==';
        $connectionString = \sprintf('DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey=%s;EndpointSuffix=core.windows.net', $accountKey);

        $output = $this->regexSecretScrubber->scrub($connectionString);

        self::assertStringNotContainsString($accountKey, $output);
        self::assertStringContainsString('***REDACTED:inline_assignment***', $output);
    }

    #[DataProvider('symfonyPlaceholderCases')]
    public function test_it_leaves_symfony_placeholder_values_unmodified(string $input): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($input, $output);
        self::assertStringNotContainsString('***REDACTED:inline_assignment***', $output);
    }

    /** @return iterable<string, array{0: string}> */
    public static function symfonyPlaceholderCases(): iterable
    {
        yield 'env_reference_in_yaml' => ["api_key: '%env(ANTHROPIC_API_KEY)%'"];
        yield 'env_reference_with_processor' => ["password: '%env(string:DB_PASSWORD)%'"];
        yield 'container_parameter_reference' => ["secret: '%kernel.secret%'"];
        yield 'shell_env_brace' => ["api_key: '\${ANTHROPIC_API_KEY}'"];
        yield 'shell_env_bare' => ["api_key: '\$ANTHROPIC_API_KEY'"];
        yield 'php_array_env_reference' => ["'api_key' => '%env(ANTHROPIC_API_KEY)%'"];
    }

    #[DataProvider('dollarValuesThatAreNoEnvironmentReferenceCases')]
    public function test_a_dollar_value_that_is_no_environment_reference_is_redacted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function dollarValuesThatAreNoEnvironmentReferenceCases(): iterable
    {
        yield 'a quoted mixed-case word' => ["password: '\$ecretValue'", "password: '***REDACTED:inline_assignment***'"];
        yield 'a double-quoted mixed-case word' => ['password: "$uperS3cret"', 'password: "***REDACTED:inline_assignment***"'];
        yield 'a php array entry holding a mixed-case word' => ["'password' => '\$ecretValue',", "'password' => '***REDACTED:inline_assignment***',"];
        yield 'a braced mixed-case word' => ['password = ${uperS3cret}', 'password = ***REDACTED:inline_assignment***'];
        yield 'a braced lower-case word in quotes' => ["api_key: '\${dbPassword}'", "api_key: '***REDACTED:inline_assignment***'"];
        yield 'a wrapped quoted mixed-case word' => ["'password' =>\n    '\$ecretValue',", "'password' =>\n'***REDACTED:multiline_assignment***',"];
    }

    #[DataProvider('codeTheAuditorMustReadCases')]
    public function test_it_leaves_code_that_merely_names_a_credential_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function codeTheAuditorMustReadCases(): iterable
    {
        yield 'a taint source read into a pass variable' => ["\$pass = \$request->request->get('pass');"];
        yield 'a query concatenating a pass column' => ["\$sql = \"SELECT * FROM users WHERE pass = '\" . \$pass . \"'\";"];
        yield 'a signing key computed by a call' => ["\$signingKey = hash_hmac('sha256', \$payload, \$userInput);"];
        yield 'an access key read from the query' => ["\$accessKey = \$request->query->get('key');"];
        yield 'a database password read from the request' => ["\$dbPass = \$_GET['db'];"];
        yield 'an array entry built from a form' => ["'pass' => \$form->get('pass')->getData(),"];
        yield 'a secret key read from a class constant' => ['$secretKey = self::DEFAULT_SECRET;'];
        yield 'a password hashed through a named argument' => ['$user = new User(password: $hasher->hashPassword($user, $plain));'];
        yield 'a password property assigned from a call' => ['$this->password = $encoder->encode($plain);'];
        yield 'a secret read from the environment' => ["'secret' => getenv('APP_SECRET'),"];
        yield 'a secret generated by nested calls' => ["'secret' => bin2hex(random_bytes(32)),"];
        yield 'a secret built by a static call' => ["'secret' => Foo::create(\$seed),"];
        yield 'a password passed on as a variable' => ["'password' => \$plain,"];
        yield 'a password hashed with a constant after the first argument' => ['$hashedPassword = password_hash($plainPassword, PASSWORD_DEFAULT);'];
        yield 'a password generated by a call without arguments' => ['$password = uniqid();'];
        yield 'a password generated from numbers' => ['$password = mt_rand(100000, 999999);'];
        yield 'a password cut from a hash of the time' => ['$password = substr(md5(time()), 0, 8);'];
        yield 'a password generated by a static call' => ['$password = Str::random(8);'];
        yield 'a secret read from a late static constant' => ['$secretKey = static::SECRET_KEY'];
        yield 'a token read from the request' => ["\$token = \$request->get('token');"];
        yield 'a token passed on as a variable' => ["'token' => \$token,"];
        yield 'a token interpolated into a query string' => ["\$url = \\sprintf('/reset?token=%s&state=%s', \$token, \$state);"];
        yield 'the csrf token id of a form login' => ["csrf_token_id: 'authenticate'"];
        yield 'the access token handler of a firewall' => ['token_handler: App\\Security\\AccessTokenHandler'];
        yield 'a constant defined from the environment' => ["define('DB_PASSWORD', getenv('DB_PASSWORD'));"];
        yield 'an xml parameter read from the environment' => ['<parameter key="mailer_password">%env(MAILER_PASSWORD)%</parameter>'];
        yield 'a password property reset to null' => ['$this->plainPassword = null;'];
        yield 'a secret entry set to null' => ["'secret' => null,"];
        yield 'a password variable set to false' => ['$password = false;'];
        yield 'a password property set to true' => ['$this->password = true;'];
        yield 'a token variable set to an upper-case NULL' => ['$token = NULL;'];
        yield 'a null default of a parameter closing the signature' => ['public function __construct(?string $password = null)'];
        yield 'a null default of a parameter followed by another' => ['public function connect(?string $password = null, ?array $options = null): self'];
        yield 'a null default of a final parameter followed by a return type' => ['public function migrate(#[\\SensitiveParameter] $credentials = null): bool'];
        yield 'a yaml secret set to null' => ['secret: null'];
        yield 'a yaml token set to true' => ['token: true'];
        yield 'a yaml credentials flag set to false' => ['persist-credentials: false'];
        yield 'a yaml flag set to an upper-case True' => ['require_ci_to_pass: True'];
        yield 'a key size set to a number' => ["'private_key_bits' => 1024,"];
        yield 'a password variable set to a number' => ['$password = 123456;'];
        yield 'a number closing an argument list' => ['new Pbkdf2(password: 100000)'];
        yield 'a signed number' => ['$password = -1000;'];
        yield 'a positive number' => ['$password = +1000,'];
        yield 'a decimal number' => ['$password = 12.50;'];
        yield 'a lower-case false in yaml' => ['secret: false'];
        yield 'an upper-case FALSE' => ['$secret = FALSE;'];
        yield 'an upper-case TRUE' => ['$secret = TRUE;'];
        yield 'a password cast to a string from a variable' => ['$password = (string) $request->get(\'password\');'];
        yield 'a password cast to a string from a short variable' => ['$password = (string) $x;'];
        yield 'a negated password variable' => ['$password = !$input;'];
        yield 'a negated password call' => ['$password = !empty($input);'];
        yield 'a password array built from variables' => ['$password = [$first, $second];'];
        yield 'a password array of form options' => ["'password' => ['label' => 'Password'],"];
        yield 'a private key type read from a global constant' => ["'private_key_type' => \\OPENSSL_KEYTYPE_RSA,"];
        yield 'a token read from a qualified class constant' => ['$token = \\App\\Security\\Token::DEFAULT;'];
        yield 'a password variable closing an argument list' => ['new User(password: $plain)'];
        yield 'a password variable closing an array' => ["foreach (['username' => \$user, 'password' => \$expectedPassword] as \$value) {"];
        yield 'a password read from the environment closing an array' => ["['username' => getenv('COUCHBASE_USER'), 'password' => getenv('COUCHBASE_PASS')]"];
        yield 'a secret read from a constant closing an argument list' => ['hash_hmac(\'sha256\', $data, secret: self::SECRET)'];
        yield 'a secret read from a class constant closing an array' => ["['secret' => Foo::SECRET]"];
        yield 'an app secret variable closing an argument list' => ['configure(app_secret: $Secr3t)'];
        yield 'a static access on a pass variable' => ['$message = str_replace("\\n", "\\n".$pass::class.\': \', trim($message));'];
        yield 'a class constant of a password constraint' => ['->setCode(NotCompromisedPassword::COMPROMISED_PASSWORD_ERROR)'];
        yield 'a class name of a credentials provider' => ['if (!class_exists(ApplicationDefaultCredentials::class)) {'];
        yield 'a parenthesised condition on a pass variable' => ['$pass = ($user || $pass) ? "$pass@" : \'\';'];
        yield 'an instance built in parentheses' => ['$credentials = (new Definition(FetchAuthTokenInterface::class))'];
        yield 'a token built by nested calls' => ['$token = unserialize(serialize(new TestBrowserToken()));'];
    }

    #[DataProvider('credentialWrittenTheSymfonyOrPhpWayCases')]
    public function test_it_redacts_a_credential_written_the_way_a_symfony_or_php_file_does(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function credentialWrittenTheSymfonyOrPhpWayCases(): iterable
    {
        yield 'a pgp private key block' => ["-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF0abcdefSECRET\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----", "***REDACTED:pem_private_key***\n\n\n\n"];
        yield 'an xml parameter' => ['<parameter key="mailer_password">hunter2supersecure</parameter>', '<parameter key="mailer_password">***REDACTED:xml_parameter***</parameter>'];
        yield 'a typed xml parameter with a dotted key' => ['<parameter key="app.stripe_secret" type="string">whsec_abcdefabcdefabcdef</parameter>', '<parameter key="app.stripe_secret" type="string">***REDACTED:xml_parameter***</parameter>'];
        yield 'the default of an environment variable parameter' => ["parameters:\n    env(DATABASE_PASSWORD): 'hunter2supersecure'", "parameters:\n    env(DATABASE_PASSWORD): '***REDACTED:inline_assignment***'"];
        yield 'a php constant definition' => ["define('DB_PASSWORD', 'hunter2supersecure');", "define('DB_PASSWORD', '***REDACTED:inline_assignment***');"];
        yield 'a yaml token key' => ["telegram:\n    token: '123456789:".str_repeat('Ab1', 12)."'", "telegram:\n    token: '***REDACTED:inline_assignment***'"];
        yield 'a php token variable' => ["\$token = '".str_repeat('ab12', 8)."';", "\$token = '***REDACTED:inline_assignment***';"];
        yield 'a php token array key' => ["'token' => '".str_repeat('ab12', 8)."',", "'token' => '***REDACTED:inline_assignment***',"];
        yield 'a discord webhook url' => [self::DISCORD_WEBHOOKS.'/123456789012345678/'.str_repeat('AbCd', 17), '***REDACTED:discord_webhook_url***'];
    }

    #[DataProvider('literalsBesideCodeCases')]
    public function test_it_still_redacts_a_literal_credential_written_beside_code(string $input, string $secret): void
    {
        self::assertStringNotContainsString($secret, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function literalsBesideCodeCases(): iterable
    {
        yield 'a quoted literal concatenated with a salt' => ["'password' => 'hunter2hunter2' . \$salt,", 'hunter2hunter2'];
        yield 'a quoted literal assigned to a variable' => ["\$apiKey = 'abcdef0123456789';", 'abcdef0123456789'];
        yield 'an unquoted literal in yaml' => ['pass: s3cr3tValue', 's3cr3tValue'];
        yield 'a literal holding a parenthesis' => ['database_password: Xk9(qL2!vB7z', 'Xk9(qL2!vB7z'];
        yield 'a literal holding a double colon' => ['smtp_password: Tr0ub4dor::3xyz', 'Tr0ub4dor::3xyz'];
        yield 'an unquoted bcrypt hash' => ['password: $2y$13$abcdefghijklmnopqrstuv', 'abcdefghijklmnopqrstuv'];
        yield 'a literal starting with a dollar sign' => ['api_key: $Up3r-S3cret!', 'Up3r-S3cret'];
        yield 'a literal holding an arrow' => ['app_secret = abc->def123', 'abc->def123'];
        yield 'a quoted literal holding a quote and a dot' => ["db_pass: \"s3cr3t'.x\"", "s3cr3t'.x"];
        yield 'a literal ending in what looks like a variable' => ['api_key: Zx9$token;', 'Zx9$token'];
        yield 'a literal shaped like a call with a number' => ['password: summer(2024)', 'summer(2024)'];
        yield 'a literal shaped like an empty call' => ['api_key: secret()', 'secret()'];
        yield 'a literal carrying on after a quoted argument' => ["client_secret: abc('x')yz", "abc('x')yz"];
        yield 'a literal shaped like a constant without a terminator' => ['password: P4ss::WORD_1', 'P4ss::WORD_1'];
        yield 'a literal shaped like a static call with a number' => ['secret: Foo::bar(1)', 'Foo::bar(1)'];
        yield 'a literal carrying on after what looks like a statement end' => ['password: $Abc;def123', 'Abc;def123'];
        yield 'a literal ending in a parenthesis after a dollar sign' => ['app_secret: $Secr3t!)', 'Secr3t'];
        yield 'a literal shaped like a variable followed by more text' => ['api_key: $Abc)def123', 'def123'];
        yield 'a literal shaped like a qualified name followed by more text' => ['api_key: \\Abc-def123,', 'def123'];
        yield 'a literal shaped like an array opening on a word' => ['password: [hunter2xyz', 'hunter2xyz'];
        yield 'a literal shaped like a negated word' => ['password: !Hunter2xyz', 'Hunter2xyz'];
        yield 'a literal cast to a string' => ["password: (string) 'hunter2hunter2'", 'hunter2hunter2'];
    }

    #[DataProvider('fallbackLiteralsAfterCodeCases')]
    public function test_a_hard_coded_fallback_after_code_under_a_credential_key_is_redacted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function fallbackLiteralsAfterCodeCases(): iterable
    {
        yield 'a short ternary after a call' => ['$password = getenv("DB_PASSWORD") ?: "Zx9Qw7Lm2Pv4";', '$password = getenv("DB_PASSWORD") ?: "***REDACTED:inline_assignment***";'];
        yield 'a null coalescing after an array offset' => ['\'password\' => $_ENV["DB_PASSWORD"] ?? "Zx9Qw7Lm2Pv4",', '\'password\' => $_ENV["DB_PASSWORD"] ?? "***REDACTED:inline_assignment***",'];
        yield 'the else branch of a ternary' => ["\$password = isset(\$a) ? \$a : 'Zx9Qw7Lm2Pv4';", "\$password = isset(\$a) ? \$a : '***REDACTED:inline_assignment***';"];
        yield 'a concatenation after a short variable' => ['$password = $x . "Zx9Qw7Lm2Pv4";', '$password = $x . "***REDACTED:inline_assignment***";'];
        yield 'both branches of a ternary' => ["\$password = \$production ? 'ProdSecret123' : 'DevSecret1234';", "\$password = \$production ? '***REDACTED:inline_assignment***' : '***REDACTED:inline_assignment***';"];
        yield 'a concatenation after a call' => ["\$token = \$this->generate() . 'abcd1234efgh';", "\$token = \$this->generate() . '***REDACTED:inline_assignment***';"];
        yield 'a fallback starting right after a slash' => ["\$password = \$a ?: 'x/Zx9Qw7Lm2Pv4';", "\$password = \$a ?: '***REDACTED:inline_assignment***';"];
        yield 'a fallback after a literal' => ["password: hunter2xx ?: 'Zx9Qw7Lm2Pv4'", "password: ***REDACTED:inline_assignment*** ?: '***REDACTED:inline_assignment***'"];
        yield 'a fallback of exactly four characters' => ["\$password = getenv('DB_PASSWORD') ?: 'abcd';", "\$password = getenv('DB_PASSWORD') ?: '***REDACTED:inline_assignment***';"];
        yield 'a fallback after several operands' => ["\$password = \$a ?? \$b ?? 'Zx9Qw7Lm2Pv4';", "\$password = \$a ?? \$b ?? '***REDACTED:inline_assignment***';"];
        yield 'a fallback after fifteen operands' => ['$password = $a'.str_repeat(' . $b', 14).' . "abcdefgh"', '$password = $a'.str_repeat(' . $b', 14).' . "***REDACTED:inline_assignment***"'];
        yield 'a fallback after sixteen operands' => ['$password = $a'.str_repeat(' . $b', 15).' . "abcdefgh"', '$password = $a'.str_repeat(' . $b', 15).' . "***REDACTED:inline_assignment***"'];
        yield 'a fallback after a call opening an argument list' => ["\$password = trim(\$a) ?: 'Zx9Qw7Lm2Pv4';", "\$password = trim(\$a) ?: '***REDACTED:inline_assignment***';"];
        yield 'a fallback in an array entry followed by another' => ["['password' => \$a ?: 'Zx9Qw7Lm2Pv4', 'user' => 'bob']", "['password' => \$a ?: '***REDACTED:inline_assignment***', 'user' => 'bob']"];
    }

    #[DataProvider('fallbacksThatHoldNoSecretCases')]
    public function test_a_fallback_after_code_that_holds_no_secret_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function fallbacksThatHoldNoSecretCases(): iterable
    {
        yield 'an empty fallback' => ["\$password = getenv('DB_PASSWORD') ?: '';"];
        yield 'a fallback of three characters' => ["\$password = getenv('DB_PASSWORD') ?: 'abc';"];
        yield 'a fallback that is a reference' => ["\$password = \$a ?? '%env(DB_PASSWORD)%';"];
        yield 'a fallback that is a redaction placeholder' => ['$password = $a ?? \'***REDACTED:env_assignment***\';'];
        yield 'a fallback that is null' => ['$password = $request->get(\'password\') ?: null;'];
        yield 'a fallback that is code' => ['$password = $a ?? $b;'];
        yield 'a concatenation of variables' => ['$password = $hasher->hash($plain) . $salt;'];
        yield 'a literal passed as an argument' => ["\$signingKey = hash_hmac('sha256', \$payload, \$userInput);"];
        yield 'a literal after an operator that is no fallback operator' => ["\$password = \$a + 'abcdefgh';"];
        yield 'a fallback after the end of the statement' => ["\$password = \$a; \$b = \$c ?: 'abcdefgh';"];
        yield 'a fallback after an argument separator' => ["connect(password: \$a, other: \$c ?: 'abcdefgh');"];
        yield 'a path joined to a directory' => ["'Token' => \$vendorDir . '/theseer/tokenizer/src/Token.php',"];
        yield 'a path joined to a directory of the class' => ["\$token = \$this->dir . '/../var/token.json';"];
        yield 'a namespace as the fallback' => ["\$secret = \$a ?: '\\\\App\\\\Security\\\\Secret';"];
        yield 'a hidden file as the fallback' => ["\$secret = \$a ?: '.secret.json';"];
        yield 'a fallback joined to the operator' => ["\$password = \$a ?:'abcdefgh';"];
    }

    #[DataProvider('phpConstantsNamedLikeCredentialsCases')]
    public function test_a_php_constant_named_like_a_credential_keeps_its_declaration_syntax(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        $this->assertParsesAsPhp($output);
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function phpConstantsNamedLikeCredentialsCases(): iterable
    {
        yield 'a string constant that is only named like a token' => ["<?php class A { private const CSRF_TOKEN_ID = 'delete_item'; }", "<?php class A { private const CSRF_TOKEN_ID = '***REDACTED:env_assignment***'; }"];
        yield 'an integer constant' => ['<?php class A { private const MAX_KEY_LENGTH = 250; }', '<?php class A { private const MAX_KEY_LENGTH = 250; }'];
        yield 'a constant read from a class constant' => ['<?php class A { public const ATTR_SSL_KEY = '.PDO::class.'::MYSQL_ATTR_SSL_KEY; }', '<?php class A { public const ATTR_SSL_KEY = '.PDO::class.'::MYSQL_ATTR_SSL_KEY; }'];
        yield 'an array constant' => ["<?php class A {\n    private const VALID_DSN_OPTIONS = [\n        'a',\n    ];\n}", "<?php class A {\n    private const VALID_DSN_OPTIONS = [\n        'a',\n    ];\n}"];
        yield 'a constant holding a literal credential' => ["<?php class A { private const DEFAULT_PASSWORD = 'hunter2supersecure'; }", "<?php class A { private const DEFAULT_PASSWORD = '***REDACTED:env_assignment***'; }"];
        yield 'a typed constant holding a literal credential' => ['<?php class A { private const string HMAC_KEY = "zzz999aaa111"; }', '<?php class A { private const string HMAC_KEY = "***REDACTED:env_assignment***"; }'];
        yield 'a nullable typed constant' => ["<?php class A { private const ?string API_KEY = 'zzz999aaa111'; }", "<?php class A { private const ?string API_KEY = '***REDACTED:env_assignment***'; }"];
        yield 'a union typed constant' => ["<?php class A { private const int|string API_KEY = 'zzz999aaa111'; }", "<?php class A { private const int|string API_KEY = '***REDACTED:env_assignment***'; }"];
        yield 'a constant at the top of a namespace' => ["<?php\nconst DB_PW = 'hunter2supersecure';\n", "<?php\nconst DB_PW = '***REDACTED:env_assignment***';\n"];
    }

    #[DataProvider('unquotedCredentialsFollowedByCodeCases')]
    public function test_an_unquoted_credential_is_redacted_without_the_closing_syntax_that_follows_it(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function unquotedCredentialsFollowedByCodeCases(): iterable
    {
        yield 'a statement terminator' => ['$password = hunter2xx;', '$password = ***REDACTED:inline_assignment***;'];
        yield 'an argument separator' => ['connect(password: hunter2xx, port: 5432)', 'connect(password: "***REDACTED:inline_assignment***", port: 5432)'];
        yield 'a closing parenthesis' => ['connect(password: hunter2xx);', 'connect(password: "***REDACTED:inline_assignment***");'];
        yield 'a closing bracket' => ["[user: 'a', password: hunter2xx]", "[user: 'a', password: \"***REDACTED:inline_assignment***\"]"];
        yield 'a closing quote and a separator' => ["'x-api-key: hunter2xx', 'Accept: json'", "'x-api-key: ***REDACTED:inline_assignment***', 'Accept: json'"];
        yield 'a return type colon' => ['fn(string $password = hunter2xx): bool', 'fn(string $password = ***REDACTED:inline_assignment***): bool'];
        yield 'a flow mapping entry followed by a key' => ['{ password: hunter2xx, roles: [ROLE_USER] }', '{ password: "***REDACTED:inline_assignment***", roles: [ROLE_USER] }'];
        yield 'a passphrase with a comma after its first word' => ['password: correct, horse battery staple', 'password: "***REDACTED:inline_assignment***"'];
        yield 'a run of closers' => ['password = hunter2xx;;;;;;;;;;', 'password = ***REDACTED:inline_assignment***;;;;;;;;;;'];
        yield 'a double quote and a separator' => ['"x-api-key: hunter2xx", "Accept: json"', '"x-api-key: ***REDACTED:inline_assignment***", "Accept: json"'];
        yield 'a closing parenthesis before more words' => ['connect(password: hunter2xx) and more', 'connect(password: "***REDACTED:inline_assignment***") and more'];
        yield 'a closing bracket before more words' => ['[password: hunter2xx] and more', '[password: "***REDACTED:inline_assignment***"] and more'];
        yield 'a terminator before more words' => ['$password = hunter2xx; $next = 1', '$password = ***REDACTED:inline_assignment***; $next = 1'];
        yield 'a return type colon before more words' => ['fn($password = hunter2xx): bool', 'fn($password = ***REDACTED:inline_assignment***): bool'];
        yield 'a single quote before more words' => ["'x-api-key: hunter2xx' and more", "'x-api-key: ***REDACTED:inline_assignment***' and more"];
        yield 'a double quote before more words' => ['"x-api-key: hunter2xx" and more', '"x-api-key: ***REDACTED:inline_assignment***" and more'];
        yield 'a comma before a hyphenated key' => ['{ password: hunter2xx, role-name: admin }', '{ password: "***REDACTED:inline_assignment***", role-name: admin }'];
        yield 'a comma before more words' => ['password: hunter2xx, and more words', 'password: "***REDACTED:inline_assignment***"'];
        yield 'a core of exactly four characters' => ['$password = abcd;', '$password = ***REDACTED:inline_assignment***;'];
        yield 'a bare number in yaml' => ['password: 12345678', 'password: "***REDACTED:inline_assignment***"'];
        yield 'a word starting like null' => ['password: nullable1234;', 'password: ***REDACTED:inline_assignment***;'];
        yield 'a word starting like true' => ['password: true1234;', 'password: ***REDACTED:inline_assignment***;'];
        yield 'a word ending like false' => ['password: notfalse;', 'password: ***REDACTED:inline_assignment***;'];
        yield 'a number followed by letters' => ['password: 1234abcd;', 'password: ***REDACTED:inline_assignment***;'];
        yield 'letters followed by a number' => ['password: abcd1234;', 'password: ***REDACTED:inline_assignment***;'];
        yield 'a cast before a quoted literal' => ["\$password = (string) 'hunter2hunter2';", "\$password = (string) '***REDACTED:inline_assignment***';"];
        yield 'a cast before an unquoted literal' => ['$password = (int) hunter2xx;', '$password = (int) ***REDACTED:inline_assignment***;'];
    }

    #[DataProvider('valuesTooShortOnceTheirClosersAreSetAsideCases')]
    public function test_a_value_of_fewer_than_four_characters_once_its_closers_are_set_aside_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function valuesTooShortOnceTheirClosersAreSetAsideCases(): iterable
    {
        yield 'three characters and a terminator' => ['$password = abc;'];
        yield 'three characters and a closing bracket' => ["['password' => abc]"];
        yield 'only closers' => ['password: ;;;;'];
    }

    #[DataProvider('redactedYamlScalarCases')]
    public function test_a_redacted_yaml_scalar_is_quoted_so_the_document_still_parses(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        self::assertNotNull(Yaml::parse($output));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function redactedYamlScalarCases(): iterable
    {
        yield 'an unquoted password' => ['search_password: s3cretValue99', 'search_password: "***REDACTED:inline_assignment***"'];
        yield 'an unquoted password under a section' => ["ldap:\n    search_password: s3cretValue99\n    host: ldap.example.com\n", "ldap:\n    search_password: \"***REDACTED:inline_assignment***\"\n    host: ldap.example.com\n"];
        yield 'a password aligned with several spaces' => ['secret:        s3cretValue99', 'secret:        "***REDACTED:inline_assignment***"'];
        yield 'a password with a windows line ending' => ["password: s3cretValue99\r\nhost: a\r\n", "password: \"***REDACTED:inline_assignment***\"\r\nhost: a\r\n"];
        yield 'a password followed by a comment' => ['password: s3cretValue99 # the database', 'password: "***REDACTED:inline_assignment***" # the database'];
        yield 'a password in a flow mapping' => ['users: { admin: { password: s3cretValue99, roles: [ROLE_ADMIN] } }', 'users: { admin: { password: "***REDACTED:inline_assignment***", roles: [ROLE_ADMIN] } }'];
        yield 'a password last in a flow mapping' => ['user: { roles: [ROLE_USER], password: s3cretValue99 }', 'user: { roles: [ROLE_USER], password: "***REDACTED:inline_assignment***" }'];
        yield 'an aws key' => ['aws_key: '.self::AWS.'IOSFODNN7EXAMPLE', 'aws_key: "***REDACTED:aws_access_key***"'];
        yield 'a list of tokens' => ["tokens:\n    - ".self::GHP.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', "tokens:\n    - \"***REDACTED:github_token***\""];
        yield 'a bearer header' => ['Authorization: Bearer '.str_repeat('a1B2', 8), 'Authorization: "***REDACTED:bearer_token***"'];
        yield 'a jwt' => ['jwt: '.self::JWT.'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'jwt: "***REDACTED:jwt***"'];
    }

    #[DataProvider('redactedValuesThatAreNoYamlScalarCases')]
    public function test_a_redacted_value_that_does_not_start_a_yaml_scalar_is_left_unquoted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function redactedValuesThatAreNoYamlScalarCases(): iterable
    {
        yield 'a dotenv assignment' => ['API_TOKEN=should_be_redacted_too', 'API_TOKEN=***REDACTED:env_assignment***'];
        yield 'an ini assignment' => ['password = s3cretValue99', 'password = ***REDACTED:inline_assignment***'];
        yield 'a php array entry' => ["'password' => hunter2xx,", "'password' => ***REDACTED:inline_assignment***,"];
        yield 'a header inside a php string' => ["'x-api-key: hunter2xx', 'Accept: json'", "'x-api-key: ***REDACTED:inline_assignment***', 'Accept: json'"];
        yield 'a header inside a php string followed by text' => ['"x-api-key: hunter2xx and more"', '"x-api-key: ***REDACTED:inline_assignment***"'];
        yield 'a scalar already quoted' => ["password: 'hunter2hunter2'", "password: '***REDACTED:inline_assignment***'"];
        yield 'a scalar that goes on after the placeholder' => ['note: '.self::AWS.'IOSFODNN7EXAMPLE is leaked', 'note: ***REDACTED:aws_access_key*** is leaked'];
        yield 'a bearer token inside a php string' => ["'Authorization: Bearer ".str_repeat('a1B2', 8)."'", "'Authorization: ***REDACTED:bearer_token***'"];
    }

    public function test_scrubbing_an_already_scrubbed_yaml_document_changes_nothing(): void
    {
        $once = $this->regexSecretScrubber->scrub('api_key: '.self::AWS."IOSFODNN7EXAMPLE\npassword: s3cretValue99\n");

        self::assertSame("api_key: \"***REDACTED:aws_access_key***\"\npassword: \"***REDACTED:inline_assignment***\"\n", $once);
        self::assertSame($once, $this->regexSecretScrubber->scrub($once));
    }

    #[DataProvider('bearerTokenLayoutCases')]
    public function test_a_bearer_token_keeps_the_number_of_lines_it_spanned(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function bearerTokenLayoutCases(): iterable
    {
        $token = str_repeat('a1B2', 8);

        yield 'the token on the next line' => ["Authorization: Bearer\n{$token}\nnext", "Authorization: \"***REDACTED:bearer_token***\"\n\nnext"];
        yield 'spaces then a break then the token' => ["Bearer  \n  {$token}", "***REDACTED:bearer_token***\n"];
        yield 'two breaks before the token' => ["Bearer\n\n{$token}!", "***REDACTED:bearer_token***\n\n!"];
        yield 'the token on the same line' => ["Bearer {$token}\nnext", "***REDACTED:bearer_token***\nnext"];
    }

    #[DataProvider('dsnsHoldingNoCredentialCases')]
    public function test_a_dsn_without_a_credential_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function dsnsHoldingNoCredentialCases(): iterable
    {
        yield 'a doctrine messenger transport' => ['MESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0'];
        yield 'a null mailer' => ['MAILER_DSN=null://null'];
        yield 'a quoted null mailer' => ['MAILER_DSN="null://null"'];
        yield 'a single-quoted sync transport' => ["MESSENGER_TRANSPORT_DSN='sync://'"];
        yield 'a local smtp server with a port' => ['MAILER_DSN=smtp://localhost:1025'];
        yield 'a transport with several harmless options' => ['MESSENGER_TRANSPORT_DSN=doctrine://default?table_name=messages&queue_name=default&redeliver_timeout=3600'];
        yield 'a suffixed dsn name' => ['SENTRY_DSN_URL=https://sentry.example.com/1'];
        yield 'a dsn followed by a comment' => ['MAILER_DSN=null://null # no mail in dev'];
    }

    #[DataProvider('dsnsHoldingACredentialCases')]
    public function test_a_dsn_that_may_hold_a_credential_is_still_redacted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function dsnsHoldingACredentialCases(): iterable
    {
        yield 'a user and a password' => ['MAILER_DSN=smtp://user:pass@smtp.example.com:25', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'an api key as the user' => ['MAILER_DSN=sendgrid://SG.abcdefghij@default', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'an auth query parameter' => ['REDIS_DSN=redis://localhost?auth=hunter2', 'REDIS_DSN=***REDACTED:env_assignment***'];
        yield 'a password query parameter after a harmless one' => ['MESSENGER_TRANSPORT_DSN=redis://localhost?stream=a&password=hunter2', 'MESSENGER_TRANSPORT_DSN=***REDACTED:env_assignment***'];
        yield 'a token query parameter' => ['MAILER_DSN=mailgun+api://default?token=abcdef', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'a secret query parameter' => ['MAILER_DSN=ses+api://default?client_secret=abcdef', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'a credentials query parameter' => ['MAILER_DSN=ses+api://default?credentials=abcdef', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'a key query parameter' => ['MAILER_DSN=mailjet+api://default?key=abcdef', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'a parameter separated by a semicolon' => ['DATABASE_DSN=mysql://host;pwd=hunter2', 'DATABASE_DSN=***REDACTED:env_assignment***'];
        yield 'a dsn that is no url' => ['DATABASE_DSN=pgsql:host=localhost;password=hunter2', 'DATABASE_DSN=***REDACTED:env_assignment***'];
        yield 'a quoted dsn with a user' => ['MAILER_DSN="brevo+api://abcdef@default"', 'MAILER_DSN=***REDACTED:env_assignment***'];
        yield 'a name that holds no dsn word' => ['API_KEY=https://example.com/feed', 'API_KEY=***REDACTED:env_assignment***'];
        yield 'a dsn word and a credential word' => ['DSN_PASSWORD=hunter2supersecure', 'DSN_PASSWORD=***REDACTED:env_assignment***'];
    }

    public function test_a_stock_dotenv_file_raises_one_redaction_marker_for_its_one_secret(): void
    {
        $dotenv = "APP_ENV=dev\nAPP_SECRET=0123456789abcdef0123456789abcdef\nMESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0\nMAILER_DSN=null://null\n";

        self::assertSame("APP_ENV=dev\nAPP_SECRET=***REDACTED:env_assignment***\nMESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0\nMAILER_DSN=null://null\n", $this->regexSecretScrubber->scrub($dotenv));
    }

    #[DataProvider('literalsPassedToCredentialCallsCases')]
    public function test_a_literal_passed_to_a_call_that_takes_a_credential_is_redacted(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function literalsPassedToCredentialCallsCases(): iterable
    {
        yield 'a config builder secret' => ["\$framework->secret('SuperSecretValue123');", "\$framework->secret('***REDACTED:call_argument***');"];
        yield 'a double-quoted config builder secret' => ['$framework->secret("SuperSecretValue123");', '$framework->secret("***REDACTED:call_argument***");'];
        yield 'a config builder password' => ["\$security->password('hunter2hunter2');", "\$security->password('***REDACTED:call_argument***');"];
        yield 'a password setter' => ["\$user->setPassword('hunter2hunter2');", "\$user->setPassword('***REDACTED:call_argument***');"];
        yield 'an api token setter' => ["\$client->setApiToken('abcdef0123456789');", "\$client->setApiToken('***REDACTED:call_argument***');"];
        yield 'a plain password setter' => ["\$user->setPlainPassword('hunter2hunter2');", "\$user->setPlainPassword('***REDACTED:call_argument***');"];
        yield 'a bare token setter' => ["\$client->setToken('abcd1234efgh');", "\$client->setToken('***REDACTED:call_argument***');"];
        yield 'a fluent setter' => ["\$u->setName('Ada')->withSecret('abcd1234efgh')->setActive(true);", "\$u->setName('Ada')->withSecret('***REDACTED:call_argument***')->setActive(true);"];
        yield 'a static setter' => ["Settings::setPassphrase('abcd1234efgh');", "Settings::setPassphrase('***REDACTED:call_argument***');"];
        yield 'a nullsafe setter' => ["\$client?->setClientSecret('abcd1234efgh');", "\$client?->setClientSecret('***REDACTED:call_argument***');"];
        yield 'a setter with a space before the parenthesis' => ["\$user->setPassword ( 'hunter2hunter2' );", "\$user->setPassword ( '***REDACTED:call_argument***' );"];
        yield 'an upper-case setter' => ["\$user->SETPASSWORD('hunter2hunter2');", "\$user->SETPASSWORD('***REDACTED:call_argument***');"];
        yield 'a literal followed by more arguments' => ["\$user->setPassword('hunter2hunter2', true);", "\$user->setPassword('***REDACTED:call_argument***', true);"];
        yield 'a literal with an escaped quote' => ["\$user->setPassword('hunter\\'2hunter2');", "\$user->setPassword('***REDACTED:call_argument***');"];
        yield 'a literal of exactly four characters' => ["\$user->setPassword('abcd');", "\$user->setPassword('***REDACTED:call_argument***');"];
        yield 'a key and a value' => ["\$bag->set('db_password', 'hunter2hunter2');", "\$bag->set('db_password', '***REDACTED:call_argument***');"];
        yield 'a parameter named like a password' => ["\$qb->setParameter('database_password', 'hunter2hunter2');", "\$qb->setParameter('database_password', '***REDACTED:call_argument***');"];
        yield 'a named argument' => ["\$definition->arg('\$apiKey', 'abcdef0123456789');", "\$definition->arg('\$apiKey', '***REDACTED:call_argument***');"];
        yield 'a dotted parameter name' => ['$container->setParameter("app.secret", "abcdef0123456789");', '$container->setParameter("app.secret", "***REDACTED:call_argument***");'];
        yield 'a bare token key' => ["\$session->set('token', 'abcdef0123456789');", "\$session->set('token', '***REDACTED:call_argument***');"];
        yield 'a key and a value without spaces' => ["\$bag->set('db_password','hunter2hunter2');", "\$bag->set('db_password','***REDACTED:call_argument***');"];
        yield 'a key and a value on one line of a chain' => ["\$c->set('mailer_password', 'hunter2hunter2')->set('x', 1);", "\$c->set('mailer_password', '***REDACTED:call_argument***')->set('x', 1);"];
        yield 'a key decoded from a long hex literal' => ["\$key = hex2bin('00112233445566778899aabbccddeeff');", "\$key = hex2bin('***REDACTED:call_argument***');"];
        yield 'a property decoded from a long base64 literal' => ['$this->key = base64_decode("c2VjcmV0c2VjcmV0c2VjcmV0");', '$this->key = base64_decode("***REDACTED:call_argument***");'];
        yield 'a key decoded from a literal of exactly sixteen characters' => ["\$key = hex2bin('0011223344556677');", "\$key = hex2bin('***REDACTED:call_argument***');"];
        yield 'a key decoded through sodium' => ["\$cipherKey = \\sodium_hex2bin('00112233445566778899aabbccddeeff');", "\$cipherKey = \\sodium_hex2bin('***REDACTED:call_argument***');"];
        yield 'a password hashed from a literal' => ["\$hash = password_hash('admin12345', PASSWORD_DEFAULT);", "\$hash = password_hash('***REDACTED:call_argument***', PASSWORD_DEFAULT);"];
        yield 'a password verified against a literal' => ['return password_verify("letmein1", $hash);', 'return password_verify("***REDACTED:call_argument***", $hash);'];
        yield 'a pdo connection' => ["\$pdo = new PDO('mysql:host=localhost', 'root', 'hunter2hunter2');", "\$pdo = new PDO('mysql:host=localhost', 'root', '***REDACTED:call_argument***');"];
        yield 'a qualified pdo connection' => ["\$pdo = new \\PDO(\$dsn, \$user, 'hunter2hunter2', [PDO::ATTR_ERRMODE => 1]);", "\$pdo = new \\PDO(\$dsn, \$user, '***REDACTED:call_argument***', [PDO::ATTR_ERRMODE => 1]);"];
    }

    #[DataProvider('callsThatTakeNoCredentialLiteralCases')]
    public function test_a_call_that_takes_no_credential_literal_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function callsThatTakeNoCredentialLiteralCases(): iterable
    {
        yield 'a password hashed from a variable' => ['$user->setPassword($hasher->hash($plain));'];
        yield 'a password read from the environment' => ["\$user->setPassword('%env(APP_PASSWORD)%');"];
        yield 'an empty password' => ["\$user->setPassword('');"];
        yield 'a three character literal' => ["\$user->setPassword('abc');"];
        yield 'a csrf token read by id' => ["\$manager->getToken('authenticate');"];
        yield 'a csrf token checked by id' => ["\$this->isCsrfTokenValid('delete-item', \$token);"];
        yield 'a token id setter' => ["\$config->setTokenId('delete_item');"];
        yield 'a password parameter setter' => ["\$config->setPasswordParameter('_password');"];
        yield 'a token setter holding null' => ['$tokenStorage->setToken(null);'];
        yield 'a token setter holding a variable' => ['$tokenStorage->setToken($token);'];
        yield 'a form field named password' => ["\$builder->add('password', PasswordType::class);"];
        yield 'a translation of a password label' => ["\$translator->trans('password', [], 'forms');"];
        yield 'a csrf token parameter' => ["\$bag->set('csrf_token', 'abcdef0123456789');"];
        yield 'a token id parameter' => ["\$bag->setParameter('token_id', 'delete_item');"];
        yield 'a password key holding a variable' => ["\$bag->set('db_password', \$password);"];
        yield 'a password key holding a reference' => ["\$bag->set('db_password', '%env(DB_PASSWORD)%');"];
        yield 'a password key holding an empty default' => ["\$request->request->get('password', '');"];
        yield 'a non credential key holding a literal' => ["\$bag->set('locale', 'fr_FR');"];
        yield 'a password hashed into a hash variable' => ['$hash = password_hash($plain, PASSWORD_DEFAULT);'];
        yield 'a password hashed from an empty literal' => ["\$hash = password_hash('', PASSWORD_DEFAULT);"];
        yield 'a pdo connection without a password' => ["\$pdo = new PDO('sqlite::memory:');"];
        yield 'a pdo connection taking its password from a variable' => ['$pdo = new PDO($dsn, $user, $password);'];
        yield 'a pdo connection with a user only' => ["\$pdo = new PDO(\$dsn, 'root');"];
        yield 'a pdo class constant' => ['$mode = PDO::ATTR_ERRMODE;'];
        yield 'a key decoded from a literal of fifteen characters' => ["\$key = hex2bin('001122334455667');"];
        yield 'a key decoded from a short literal' => ["\$key = hex2bin('0011');"];
        yield 'a key decoded from a short literal and a long comment' => ["\$key = hex2bin('0011'); // decoded with a comment longer than sixteen characters"];
        yield 'a key decoded from a variable' => ['$key = base64_decode($encoded);'];
        yield 'a cache key hashed from a literal' => ["\$cacheKey = md5('users_list_of_the_day');"];
        yield 'a key decoded from a reference' => ["\$key = hex2bin('%env(KEY_HEX)%');"];
        yield 'another class built with literals' => ["\$mail = new Mailer('smtp://localhost', 'noreply', 'hunter2hunter2');"];
    }

    #[DataProvider('literalsAssignedToCredentialOffsetsCases')]
    public function test_a_literal_assigned_to_a_credential_named_offset_is_redacted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function literalsAssignedToCredentialOffsetsCases(): iterable
    {
        yield 'a config entry' => ["\$cfg['password'] = 'hunter2hunter2';", "\$cfg['password'] = '***REDACTED:inline_assignment***';"];
        yield 'an environment entry' => ["\$_ENV['APP_SECRET'] = 'hunter2hunter2';", "\$_ENV['APP_SECRET'] = '***REDACTED:inline_assignment***';"];
        yield 'a nested double-quoted entry' => ['$config["database"]["password"]= "hunter2hunter2";', '$config["database"]["password"]= "***REDACTED:inline_assignment***";'];
        yield 'an entry with spaces inside the brackets' => ["\$cfg['api_key']   =   'abcdef0123456789';", "\$cfg['api_key']   =   '***REDACTED:inline_assignment***';"];
    }

    #[DataProvider('offsetsThatHoldNoCredentialLiteralCases')]
    public function test_a_credential_named_offset_that_holds_no_literal_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function offsetsThatHoldNoCredentialLiteralCases(): iterable
    {
        yield 'a hash read into an entry' => ["\$row['password'] = \$hash;"];
        yield 'a token read from an object' => ["\$data['token'] = \$token->getValue();"];
        yield 'an entry compared with a literal' => ["if (\$_POST['password'] === 'letmein') {"];
        yield 'an entry read from the environment' => ["\$_ENV['APP_SECRET'] = getenv('APP_SECRET');"];
        yield 'an entry holding a reference' => ["\$cfg['password'] = '%env(DB_PASSWORD)%';"];
    }

    #[DataProvider('literalsWrappedInAPureFunctionCases')]
    public function test_a_literal_wrapped_in_a_pure_function_under_a_credential_key_is_redacted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function literalsWrappedInAPureFunctionCases(): iterable
    {
        yield 'a key decoded from hex' => ["\$encryptionKey = hex2bin('00112233445566778899aabbccddeeff');", "\$encryptionKey = hex2bin('***REDACTED:inline_assignment***');"];
        yield 'a password hashed with an algorithm' => ["\$password = password_hash('admin12345', PASSWORD_DEFAULT);", "\$password = password_hash('***REDACTED:inline_assignment***', PASSWORD_DEFAULT);"];
        yield 'a secret decoded from base64' => ["'secret' => base64_decode('c2VjcmV0c2VjcmV0'),", "'secret' => base64_decode('***REDACTED:inline_assignment***'),"];
        yield 'a key encoded to base64' => ['$apiKey = base64_encode("abcdef0123456789");', '$apiKey = base64_encode("***REDACTED:inline_assignment***");'];
        yield 'a key trimmed from the root namespace' => ["\$apiKey = \\trim('  abcdef0123456789  ');", "\$apiKey = \\trim('***REDACTED:inline_assignment***');"];
        yield 'a password lower-cased' => ["\$password = strtolower('HunterTwo2024');", "\$password = strtolower('***REDACTED:inline_assignment***');"];
        yield 'a password upper-cased' => ["\$password = strtoupper('hunter2hunter2');", "\$password = strtoupper('***REDACTED:inline_assignment***');"];
        yield 'a password hashed with md5' => ["\$password = md5('hunter2hunter2');", "\$password = md5('***REDACTED:inline_assignment***');"];
        yield 'a password hashed with sha1' => ["\$password = sha1('hunter2hunter2');", "\$password = sha1('***REDACTED:inline_assignment***');"];
        yield 'a key converted to binary' => ["\$secretKey = bin2hex('hunter2hunter2');", "\$secretKey = bin2hex('***REDACTED:inline_assignment***');"];
        yield 'a key decoded from a url' => ["\$secretKey = urldecode('hunter2%20hunter2');", "\$secretKey = urldecode('***REDACTED:inline_assignment***');"];
        yield 'a call with a space after the parenthesis' => ["\$password = md5( 'hunter2hunter2' );", "\$password = md5( '***REDACTED:inline_assignment***' );"];
        yield 'a key decoded from sodium hex' => ["\$secretKey = sodium_hex2bin('00112233445566778899aabbccddeeff');", "\$secretKey = sodium_hex2bin('***REDACTED:inline_assignment***');"];
    }

    #[DataProvider('callsAroundNoLiteralUnderACredentialKeyCases')]
    public function test_a_call_that_wraps_no_literal_under_a_credential_key_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function callsAroundNoLiteralUnderACredentialKeyCases(): iterable
    {
        yield 'a password hashed from a variable' => ['$password = password_hash($plain, PASSWORD_DEFAULT);'];
        yield 'a key generated at random' => ['$secretKey = bin2hex(random_bytes(32));'];
        yield 'a key decoded from the environment' => ["\$encryptionKey = hex2bin(getenv('KEY_HEX'));"];
        yield 'a hash whose first argument names the algorithm' => ["\$signingKey = hash_hmac('sha256', \$payload, \$userInput);"];
        yield 'a wrapped reference' => ["\$password = md5('%env(SALT)%');"];
        yield 'a wrapped empty literal' => ["\$password = md5('');"];
        yield 'a function that is no wrapper' => ["\$password = generate_password('hunter2hunter2');"];
    }

    #[DataProvider('xmlArgumentsCases')]
    public function test_an_xml_service_argument_named_like_a_credential_is_redacted(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function xmlArgumentsCases(): iterable
    {
        yield 'a named argument' => ['<argument key="$apiKey">abcdef0123456789</argument>', '<argument key="$apiKey">***REDACTED:xml_parameter***</argument>'];
        yield 'a typed password argument' => ['<argument type="string" key="$password">hunter2hunter2</argument>', '<argument type="string" key="$password">***REDACTED:xml_parameter***</argument>'];
        yield 'a single-quoted key' => ["<argument key='\$clientSecret'>hunter2hunter2</argument>", "<argument key='\$clientSecret'>***REDACTED:xml_parameter***</argument>"];
        yield 'an argument next to a parameter' => ["<parameter key=\"mailer_password\">hunter2hunter2</parameter>\n<argument key=\"\$apiKey\">abcdef0123456789</argument>", "<parameter key=\"mailer_password\">***REDACTED:xml_parameter***</parameter>\n<argument key=\"\$apiKey\">***REDACTED:xml_parameter***</argument>"];
    }

    #[DataProvider('xmlArgumentsThatHoldNoCredentialCases')]
    public function test_an_xml_service_argument_that_holds_no_credential_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function xmlArgumentsThatHoldNoCredentialCases(): iterable
    {
        yield 'a reference' => ['<argument key="$apiKey">%env(API_KEY)%</argument>'];
        yield 'an argument named like a label' => ['<argument key="$label">hunter2hunter2</argument>'];
        yield 'an argument without a key' => ['<argument>hunter2hunter2</argument>'];
        yield 'a service reference' => ['<argument key="$apiKey" type="service" id="app.api_key"/>'];
    }

    #[DataProvider('yamlBlockScalarCases')]
    public function test_a_yaml_block_scalar_under_a_credential_key_is_redacted_and_the_document_still_parses(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
        self::assertNotNull(Yaml::parse($output));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function yamlBlockScalarCases(): iterable
    {
        yield 'a literal block' => ["secret: |\n    hunter2hunter2\n    second line\nnext: 1", "secret: |\n    ***REDACTED:block_scalar***\n\nnext: 1"];
        yield 'a folded block that strips the last newline' => ["password: >-\n    hunter2hunter2\nnext: 1", "password: >-\n    ***REDACTED:block_scalar***\nnext: 1"];
        yield 'a block that keeps trailing newlines' => ["api_key: |+\n  abcdef0123456789\n\n  more\nnext: 1", "api_key: |+\n  ***REDACTED:block_scalar***\n\n\nnext: 1"];
        yield 'a block with an indentation indicator' => ["secret: |2\n    hunter2hunter2\nnext: 1", "secret: |2\n    ***REDACTED:block_scalar***\nnext: 1"];
        yield 'a block nested in a mapping' => ["framework:\n    secret: |\n        hunter2hunter2\n    other: 1\n", "framework:\n    secret: |\n        ***REDACTED:block_scalar***\n    other: 1\n"];
        yield 'a block in a list item' => ["credentials:\n    - password: |\n          hunter2hunter2\n      name: a\n", "credentials:\n    - password: |\n          ***REDACTED:block_scalar***\n      name: a\n"];
        yield 'a block with a comment after the indicator' => ["secret: | # kept\n    hunter2hunter2\nnext: 1", "secret: | # kept\n    ***REDACTED:block_scalar***\nnext: 1"];
        yield 'a block ending the file without a newline' => ["secret: |\n    hunter2hunter2", "secret: |\n    ***REDACTED:block_scalar***"];
        yield 'a block with an empty line inside' => ["secret: |\n    first part\n\n    second part\nnext: 1", "secret: |\n    ***REDACTED:block_scalar***\n\n\nnext: 1"];
        yield 'a block with windows line endings' => ["secret: |\r\n    hunter2hunter2\r\nnext: 1", "secret: |\n    ***REDACTED:block_scalar***\nnext: 1"];
    }

    #[DataProvider('yamlBlockScalarsThatHoldNoCredentialCases')]
    public function test_a_yaml_block_scalar_that_holds_no_credential_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function yamlBlockScalarsThatHoldNoCredentialCases(): iterable
    {
        yield 'a block under another key' => ["description: |\n    hunter2hunter2\nnext: 1"];
        yield 'a block that is empty' => ["secret: |\nnext: 1"];
        yield 'a block of blank lines' => ["secret: |\n  \n\n   \nnext: 1"];
        yield 'a block whose next line is not indented' => ["secret: |\nhunter2hunter2\n"];
        yield 'a reference on a block key' => ["secret: '%env(APP_SECRET)%'\n    indented: line\n"];
        yield 'a plain scalar' => ["secret: abc\n    continued\n"];
    }

    #[DataProvider('truncatedPrivateKeyCases')]
    public function test_a_private_key_cut_before_its_end_marker_is_redacted_to_the_end_of_its_body(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function truncatedPrivateKeyCases(): iterable
    {
        $line = 'MIIEowIBAAKCAQEAxYZabcdef';

        yield 'a key cut after two lines' => ["-----BEGIN RSA PRIVATE KEY-----\n{$line}\n{$line}", "***REDACTED:pem_private_key***\n\n"];
        yield 'a key cut after a line break' => ["-----BEGIN PRIVATE KEY-----\n{$line}\n", "***REDACTED:pem_private_key***\n\n"];
        yield 'a key cut and followed by other text' => ["a: 1\n-----BEGIN OPENSSH PRIVATE KEY-----\n{$line}\n{$line}\n\nb: 2\n", "a: 1\n***REDACTED:pem_private_key***\n\n\n\nb: 2\n"];
        yield 'a pgp key with a blank line after its header' => ["-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF0abcdefSECRETvalue\n=abcd", "***REDACTED:pem_private_key***\n\n\n=abcd"];
        yield 'a key with windows line endings' => ["-----BEGIN EC PRIVATE KEY-----\r\n{$line}\r\n{$line}", "***REDACTED:pem_private_key***\n\n"];
        yield 'an indented key cut in a yaml block' => ["key: |\n  -----BEGIN PRIVATE KEY-----\n  {$line}\n  {$line}\n", "key: |\n  ***REDACTED:pem_private_key***\n\n\n"];
    }

    #[DataProvider('privateKeyHeadersWithoutAKeyCases')]
    public function test_a_private_key_header_followed_by_no_key_material_is_left_readable(string $input): void
    {
        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string}> */
    public static function privateKeyHeadersWithoutAKeyCases(): iterable
    {
        yield 'a header quoted in code' => ["if (str_contains(\$pem, '-----BEGIN PRIVATE KEY-----')) {\n    return true;\n}"];
        yield 'a header alone' => ['-----BEGIN PRIVATE KEY-----'];
        yield 'a header followed by prose' => ["-----BEGIN PRIVATE KEY-----\nthis is a header\n"];
        yield 'a header followed by a short line' => ["-----BEGIN PRIVATE KEY-----\nabc123\n"];
        yield 'a public key' => ["-----BEGIN PUBLIC KEY-----\nMIIEowIBAAKCAQEAxYZabcdef\n"];
    }

    #[DataProvider('unterminatedQuotedEnvValueCases')]
    public function test_an_environment_value_whose_quote_is_never_closed_is_redacted_to_the_end_of_the_line(string $input, string $expected): void
    {
        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function unterminatedQuotedEnvValueCases(): iterable
    {
        yield 'a double quote' => ['APP_SECRET="a b c', 'APP_SECRET=***REDACTED:env_assignment***'];
        yield 'a single quote' => ["MAIL_PASSWORD='super secret passphrase", 'MAIL_PASSWORD=***REDACTED:env_assignment***'];
        yield 'a quote with lines around it' => ["A=1\nAPP_SECRET=\"a b c\nOTHER=2\n", "A=1\nAPP_SECRET=***REDACTED:env_assignment***\nOTHER=2\n"];
        yield 'a quote with an escaped quote inside' => ['APP_SECRET="a \\" b', 'APP_SECRET=***REDACTED:env_assignment***'];
        yield 'a quote followed by a windows line ending' => ["APP_SECRET=\"a b c\r\nOTHER=2", "APP_SECRET=***REDACTED:env_assignment***\r\nOTHER=2"];
        yield 'a closed quote is still redacted on its own' => ['APP_SECRET="a b c" # note', 'APP_SECRET=***REDACTED:env_assignment*** # note'];
    }

    #[DataProvider('longOpenAiKeyCases')]
    public function test_an_openai_key_is_redacted_whatever_its_length(string $key): void
    {
        $output = $this->regexSecretScrubber->scrub("OPENAI = {$key} end");

        self::assertSame('OPENAI = ***REDACTED:openai_api_key*** end', $output);
    }

    /** @return iterable<string, array{0: string}> */
    public static function longOpenAiKeyCases(): iterable
    {
        yield 'twenty characters' => ['sk-'.str_repeat('a1B2', 5)];
        yield 'exactly two hundred characters' => ['sk-'.str_repeat('a1B2', 50)];
        yield 'two hundred and one characters' => ['sk-'.str_repeat('a1B2', 50).'c'];
        yield 'a project key of three hundred characters' => ['sk-proj-'.str_repeat('a1B2', 75)];
        yield 'a key of a few thousand characters' => ['sk-'.str_repeat('a1B2_-', 700)];
    }

    public function test_a_word_that_merely_ends_in_sk_is_no_openai_key(): void
    {
        $input = 'the task-'.str_repeat('a1B2', 8).' and the sk-short';

        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    public function test_it_leaves_non_credential_content_unmodified(): void
    {
        $code = "<?php\n\nclass UserController {\n    public function indexAction(): Response\n    {\n        return new Response('hello');\n    }\n}\n";

        self::assertSame($code, $this->regexSecretScrubber->scrub($code));
    }

    public function test_it_returns_empty_string_unmodified(): void
    {
        self::assertSame('', $this->regexSecretScrubber->scrub(''));
    }

    public function test_scrub_is_idempotent(): void
    {
        $input = "STRIPE_SECRET_KEY=sk_super_secret_123\nAWS=".self::AWS."IOSFODNN7EXAMPLE\n";

        $once = $this->regexSecretScrubber->scrub($input);
        $twice = $this->regexSecretScrubber->scrub($once);

        self::assertSame($once, $twice);
    }

    public function test_scrubbing_credentials_written_as_call_arguments_blocks_and_truncated_keys_is_idempotent(): void
    {
        $input = "\$user->setPassword('hunter2hunter2');\n\$bag->set('db_password', 'hunter2hunter2');\n\$cfg['password'] = md5('hunter2hunter2');\n"
            ."<argument key=\"\$apiKey\">abcdef0123456789</argument>\nsecret: |\n    hunter2hunter2\nAPP_SECRET=\"a b c\n"
            .'sk-'.str_repeat('a1B2', 60)."\n-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEAxYZabcdef\n";

        $once = $this->regexSecretScrubber->scrub($input);

        self::assertStringNotContainsString('hunter2hunter2', $once);
        self::assertSame($once, $this->regexSecretScrubber->scrub($once));
    }

    public function test_multiple_secrets_in_same_input_are_all_redacted(): void
    {
        // Mix free-floating tokens (caught by their specific regex) with env-style assignments
        // (caught by env_assignment). Asserts both code paths fire in a single call.
        $input = 'Token: '.self::AWS."IOSFODNN7EXAMPLE\nGitHub: ".self::GHP."_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\nAPI_TOKEN=should_be_redacted_too\n";

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertStringNotContainsString(self::AWS.'IOSFODNN7EXAMPLE', $output);
        self::assertStringNotContainsString(self::GHP.'_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', $output);
        self::assertStringNotContainsString('should_be_redacted_too', $output);
        self::assertStringContainsString('***REDACTED:aws_access_key***', $output);
        self::assertStringContainsString('***REDACTED:github_token***', $output);
        self::assertStringContainsString('***REDACTED:env_assignment***', $output);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_additional_patterns_are_applied(): void
    {
        $regexSecretScrubber = new RegexSecretScrubber(additionalPatterns: ['/INTERNAL-[A-Z0-9]{12}/']);

        $output = $regexSecretScrubber->scrub('reference: INTERNAL-ABC123DEF456');

        self::assertStringNotContainsString('INTERNAL-ABC123DEF456', $output);
        self::assertStringContainsString('***REDACTED:custom_0***', $output);
    }

    public function test_inline_assignment_redaction_preserves_key_and_quotes(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: "supersecretvalue"');

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    public function test_unquoted_inline_assignment_is_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: supersecretvalue');

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    #[DataProvider('additionalInlineCredentialKeyCases')]
    public function test_inline_assignment_redacts_additional_credential_keys(string $key): void
    {
        $output = $this->regexSecretScrubber->scrub(\sprintf('%s: "aVeryLongSecretValue123"', $key));

        self::assertSame(\sprintf('%s: "***REDACTED:inline_assignment***"', $key), $output);
    }

    /** @return iterable<string, array{string}> */
    public static function additionalInlineCredentialKeyCases(): iterable
    {
        yield 'passwd' => ['passwd'];
        yield 'pwd' => ['pwd'];
        yield 'private_key' => ['private_key'];
        yield 'auth_token' => ['auth_token'];
        yield 'api_token' => ['api_token'];
        yield 'api-token' => ['api-token'];
        yield 'credentials' => ['credentials'];
        yield 'passphrase' => ['passphrase'];
    }

    public function test_it_redacts_an_encrypted_pem_private_key(): void
    {
        $output = $this->regexSecretScrubber->scrub("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBVQIBADANBg\n-----END ENCRYPTED PRIVATE KEY-----");

        self::assertStringContainsString('***REDACTED:pem_private_key***', $output);
        self::assertStringNotContainsString('MIIBVQIBADANBg', $output);
    }

    public function test_unquoted_inline_assignment_leaves_symfony_placeholder_unmodified(): void
    {
        $input = 'api_key: %env(ANTHROPIC_API_KEY)%';

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($input, $output);
    }

    public function test_inline_assignment_with_an_empty_value_does_not_swallow_the_next_lines_secret(): void
    {
        $output = $this->regexSecretScrubber->scrub("password:\nsecret: hunter2ProdPassword");

        self::assertSame("password:\nsecret: \"***REDACTED:inline_assignment***\"", $output);
    }

    public function test_unquoted_all_caps_key_value_is_only_redacted_once_by_env_assignment(): void
    {
        $output = $this->regexSecretScrubber->scrub('PASSWORD=hunter2supersecure');

        self::assertSame('PASSWORD=***REDACTED:env_assignment***', $output);
    }

    public function test_env_assignment_redaction_preserves_key_prefix(): void
    {
        $output = $this->regexSecretScrubber->scrub('STRIPE_SECRET_KEY=sk_super_secret_value');

        self::assertSame('STRIPE_SECRET_KEY=***REDACTED:env_assignment***', $output);
    }

    public function test_env_assignment_with_an_empty_value_does_not_swallow_the_next_lines_secret(): void
    {
        $output = $this->regexSecretScrubber->scrub("APP_SECRET=\nDB_PASSWORD=hunter2ProdPassword");

        self::assertSame("APP_SECRET=\nDB_PASSWORD=***REDACTED:env_assignment***", $output);
    }

    public function test_env_assignment_redacts_a_double_quoted_value_containing_spaces(): void
    {
        $output = $this->regexSecretScrubber->scrub('APP_SECRET="correct horse battery staple"');

        self::assertSame('APP_SECRET=***REDACTED:env_assignment***', $output);
    }

    public function test_env_assignment_redacts_a_single_quoted_value_containing_spaces(): void
    {
        $output = $this->regexSecretScrubber->scrub("MAIL_PASSWORD='super secret passphrase here'");

        self::assertSame('MAIL_PASSWORD=***REDACTED:env_assignment***', $output);
    }

    public function test_env_assignment_redacts_a_double_quoted_value_containing_an_escaped_quote(): void
    {
        $output = $this->regexSecretScrubber->scrub('PASSWORD="ab\"cd1234"');

        self::assertSame('PASSWORD=***REDACTED:env_assignment***', $output);
    }

    public function test_inline_assignment_redacts_a_double_quoted_value_containing_an_escaped_quote(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: "abcd\"ef1234"');

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    public function test_env_assignment_fully_redacts_a_double_quoted_value_containing_an_unescaped_apostrophe(): void
    {
        $output = $this->regexSecretScrubber->scrub('MAIL_PASSWORD="don\'t tell anyone 2024!"');

        self::assertSame('MAIL_PASSWORD=***REDACTED:env_assignment***', $output);
    }

    public function test_inline_assignment_fully_redacts_a_single_quoted_value_containing_an_unescaped_double_quote(): void
    {
        $output = $this->regexSecretScrubber->scrub('api_key: \'sk_it"s_a_fake_secret_key_1234\'');

        self::assertSame("api_key: '***REDACTED:inline_assignment***'", $output);
    }

    public function test_unquoted_inline_assignment_redacts_a_multi_word_value(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: hunter2 secret pass phrase');

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    public function test_a_value_wrapped_to_the_next_line_is_still_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub("\$config = [\n    'password' =>\n        'SuperSecretValue1234',\n];");

        self::assertSame("\$config = [\n    'password' =>\n'***REDACTED:multiline_assignment***',\n];", $output);
    }

    public function test_a_wrapped_quoted_literal_shaped_like_php_code_is_still_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub("\$config = [\n    'password' =>\n        '\$Pa55->w0rd1234',\n];");

        self::assertSame("\$config = [\n    'password' =>\n'***REDACTED:multiline_assignment***',\n];", $output);
    }

    public function test_a_wrapped_value_under_a_credential_key_with_trailing_segments_is_still_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub("\$config = [\n    'client_secret_value' =>\n        'SuperSecretValue1234',\n];");

        self::assertSame("\$config = [\n    'client_secret_value' =>\n'***REDACTED:multiline_assignment***',\n];", $output);
    }

    #[DataProvider('multilineAssignmentLayoutCases')]
    public function test_a_multiline_secret_keeps_the_number_of_lines_it_spanned(string $input, string $expected): void
    {
        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($expected, $output);
        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function multilineAssignmentLayoutCases(): iterable
    {
        yield 'a break before the delimiter and another after it' => ["password\n: \n'SuperSecretValue1234'", "password\n:\n'***REDACTED:multiline_assignment***'"];
        yield 'a break before the delimiter only' => ["'password'\n=> 'SuperSecretValue1234'", "'password'\n=> '***REDACTED:inline_assignment***'"];
        yield 'a break before a fat arrow and another after it' => ["'password'\n=>\n'SuperSecretValue1234'", "'password'\n=>\n'***REDACTED:multiline_assignment***'"];
        yield 'two breaks before the delimiter' => ["secret\n\n=\n'SuperSecretValue1234'", "secret\n\n=\n'***REDACTED:multiline_assignment***'"];
        yield 'a break after the delimiter only' => ["password:\n  'SuperSecretValue1234'", "password:\n'***REDACTED:multiline_assignment***'"];
        yield 'windows line endings' => ["password:\r\n  'SuperSecretValue1234'", "password:\n'***REDACTED:multiline_assignment***'"];
    }

    public function test_a_symfony_placeholder_wrapped_to_the_next_line_is_left_unmodified(): void
    {
        $input = "\$config = [\n    'password' =>\n        '%env(APP_SECRET)%',\n];";

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame($input, $output);
    }

    public function test_a_value_wrapped_to_the_next_line_containing_an_escaped_quote_is_fully_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub("password:\n  \"abcd\\\"efgh\"\n");

        self::assertSame("password:\n\"***REDACTED:multiline_assignment***\"\n", $output);
    }

    public function test_a_value_wrapped_to_the_next_line_containing_an_unescaped_apostrophe_is_fully_redacted(): void
    {
        $output = $this->regexSecretScrubber->scrub("password:\n  \"don't tell anyone\"\n");

        self::assertSame("password:\n\"***REDACTED:multiline_assignment***\"\n", $output);
    }

    public function test_redacting_a_value_wrapped_to_the_next_line_preserves_the_total_line_count(): void
    {
        $input = "\$config = [\n    'password' =>\n        'SuperSecretValue1234',\n];";

        $output = $this->regexSecretScrubber->scrub($input);

        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
    }

    public function test_redacting_a_pem_private_key_preserves_the_total_line_count(): void
    {
        $pem = "-----BEGIN RSA PRIVATE KEY-----\n".implode("\n", array_fill(0, 5, 'MIIEowIBAAKCAQEAxYZ'))."\n-----END RSA PRIVATE KEY-----\n";
        $input = "<?php\n\$key = <<<PEM\n{$pem}PEM;\n\$dangerous = eval(\$_GET['code']);\n";

        $output = $this->regexSecretScrubber->scrub($input);

        $outputLines = explode("\n", $output);
        self::assertSame(substr_count($input, "\n"), substr_count($output, "\n"));
        self::assertStringContainsString('eval(', $outputLines[10]);
    }

    public function test_env_assignment_redacts_a_value_containing_a_literal_hash_character(): void
    {
        $output = $this->regexSecretScrubber->scrub('APP_SECRET=abc#def123whichshouldstillberedacted');

        self::assertSame('APP_SECRET=***REDACTED:env_assignment***', $output);
    }

    public function test_unquoted_inline_assignment_redacts_a_value_containing_a_literal_hash_character(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: correcthorse#batterystaple');

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    #[DataProvider('midWordCredentialKeyCases')]
    public function test_env_assignment_redacts_credential_word_anywhere_in_the_key(string $key, string $value): void
    {
        $output = $this->regexSecretScrubber->scrub(\sprintf('%s=%s', $key, $value));

        self::assertSame(\sprintf('%s=***REDACTED:env_assignment***', $key), $output);
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function midWordCredentialKeyCases(): iterable
    {
        yield 'secret_as_prefix_segment' => ['SECRET_KEY_BASE', 'zzz999aaa111'];
        yield 'password_as_middle_segment' => ['MAILER_PASSWORD_ENC', 'qwerty12345'];
        yield 'token_as_prefix_segment' => ['TOKEN_STORE', 'leakme123456'];
        yield 'key_as_middle_segment' => ['JWT_PRIVATE_KEY_PATH', '/var/secrets/jwt.pem'];
        yield 'key_as_suffix_segment_with_prefix' => ['AWS_ACCESS_KEY_ID', 'AKIAABCDEFGHEXAMPLE'];
        yield 'passphrase_as_suffix_segment' => ['SSH_PASSPHRASE', 'hunter2000'];
        yield 'glued_api_key' => ['APIKEY', 'zzz999aaa111'];
        yield 'glued_auth_key' => ['AUTHKEY', 'zzz999aaa111'];
        yield 'glued_access_key' => ['ACCESSKEY', 'zzz999aaa111'];
        yield 'glued_db_pass' => ['DBPASS', 'hunter2supersecure'];
        yield 'glued_pass_key' => ['PASSKEY', 'zzz999aaa111'];
        yield 'glued_secret_access_key_after_a_prefix_segment' => ['AWS_SECRETACCESSKEY', 'zzz999aaa111'];
        yield 'glued_api_key_before_a_suffix_segment' => ['APIKEY_2', 'zzz999aaa111'];
        yield 'glued_refresh_token' => ['REFRESHTOKEN', 'zzz999aaa111'];
    }

    #[DataProvider('inlineCredentialKeyWithTrailingSegmentCases')]
    public function test_inline_assignment_redacts_a_credential_key_followed_by_further_segments(string $key): void
    {
        $output = $this->regexSecretScrubber->scrub(\sprintf("%s: 'zzz999aaa111'", $key));

        self::assertSame(\sprintf("%s: '***REDACTED:inline_assignment***'", $key), $output);
    }

    /** @return iterable<string, array{0: string}> */
    public static function inlineCredentialKeyWithTrailingSegmentCases(): iterable
    {
        yield 'aws_secret_access_key' => ['aws_secret_access_key'];
        yield 'secret_key_base' => ['secret_key_base'];
        yield 'client_secret_value' => ['client_secret_value'];
        yield 'private_key_path' => ['private_key_path'];
    }

    #[DataProvider('nonCredentialKeyContainingCredentialSubstringCases')]
    public function test_env_assignment_does_not_redact_keys_containing_a_credential_word_as_a_bare_substring(string $line): void
    {
        self::assertSame($line, $this->regexSecretScrubber->scrub($line));
    }

    /** @return iterable<string, array{0: string}> */
    public static function nonCredentialKeyContainingCredentialSubstringCases(): iterable
    {
        yield 'monkey_contains_key' => ['MONKEY_COUNT=5'];
        yield 'keyspace_contains_key' => ['SESSION_KEYSPACE=xyz'];
        yield 'keyword_contains_key' => ['MY_KEYWORD_VALUE=abc'];
        yield 'compass_ends_in_pass' => ['COMPASS=north'];
        yield 'turkey_ends_in_key' => ['TURKEY_REGION=eu'];
        yield 'hockey_ends_in_key' => ['HOCKEY=puck'];
    }

    #[DataProvider('gluedInlineCredentialKeyCases')]
    public function test_inline_assignment_redacts_a_credential_word_glued_to_its_qualifier(string $key): void
    {
        $output = $this->regexSecretScrubber->scrub(\sprintf("%s: 'zzz999aaa111'", $key));

        self::assertSame(\sprintf("%s: '***REDACTED:inline_assignment***'", $key), $output);
    }

    /** @return iterable<string, array{0: string}> */
    public static function gluedInlineCredentialKeyCases(): iterable
    {
        yield 'secretkey' => ['secretkey'];
        yield 'authkey' => ['authkey'];
        yield 'accesskey' => ['accesskey'];
        yield 'dbpass' => ['dbpass'];
        yield 'dbPassword' => ['dbPassword'];
        yield 'appSecret' => ['appSecret'];
        yield 'masterKey' => ['masterKey'];
        yield 'refreshToken' => ['refreshToken'];
        yield 'root_passwd' => ['root_passwd'];
    }

    public function test_words_that_merely_contain_a_glued_credential_word_are_not_inline_credentials(): void
    {
        $input = "compass: 'north123'\n'bypass' => 'cache1'\nturkey: 'region1'\n";

        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    public function test_vendor_token_prefixes_on_ordinary_words_are_not_credentials(): void
    {
        $input = "npm_install\nhf_hub_download()\nglpat-example\nSG.Example\npypi-simple-index\n";

        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }

    public function test_connection_uri_redaction_preserves_scheme_and_host(): void
    {
        $output = $this->regexSecretScrubber->scrub('DATABASE_URL=postgres://app_user:s3cr3tValue@db.internal:5432/app');

        self::assertSame('DATABASE_URL=postgres://***REDACTED:connection_uri***@db.internal:5432/app', $output);
    }

    public function test_connection_uri_redaction_covers_a_password_containing_an_at_sign(): void
    {
        $output = $this->regexSecretScrubber->scrub('DATABASE_URL=postgres://appuser:p@ssw0rd@db.example.com:5432/appdb');

        self::assertSame('DATABASE_URL=postgres://***REDACTED:connection_uri***@db.example.com:5432/appdb', $output);
    }

    public function test_google_api_key_ending_in_a_non_word_character_is_still_redacted(): void
    {
        $key = self::GOOGLE.str_repeat('a', 34).'-';
        $output = $this->regexSecretScrubber->scrub("analytics_key: {$key}\nnext_line: unrelated");

        self::assertStringNotContainsString($key, $output);
        self::assertStringContainsString('***REDACTED:google_api_key***', $output);
    }

    public function test_it_leaves_credential_free_urls_unmodified(): void
    {
        $url = 'see https://example.com:8080/docs?token=public for details';

        self::assertSame($url, $this->regexSecretScrubber->scrub($url));
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_a_pattern_that_cannot_be_evaluated_withholds_the_content_instead_of_shipping_it_part_scanned(): void
    {
        $regexSecretScrubber = new RegexSecretScrubber(additionalPatterns: ['/^(a+)+$/']);

        $output = $this->underATightBacktrackLimit(static fn (): string => $regexSecretScrubber->scrub(str_repeat('a', 30)."b\nSECONDARY-123"));

        self::assertSame("***REDACTED:unscannable***\n", $output);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_it_reports_the_pattern_it_could_not_evaluate(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                'Withheld file content: a secret-scrubbing pattern could not be evaluated',
                self::callback(static fn (array $context): bool => 'custom_0' === ($context['pattern'] ?? null) && \is_string($context['error'] ?? null) && '' !== $context['error']),
            );

        $regexSecretScrubber = new RegexSecretScrubber(['/^(a+)+$/'], $logger);

        self::assertSame(
            '***REDACTED:unscannable***',
            $this->underATightBacktrackLimit(static fn (): string => $regexSecretScrubber->scrub(str_repeat('a', 30).'b')),
        );
    }

    /**
     * @param callable(): string $scrub
     */
    private function underATightBacktrackLimit(callable $scrub): string
    {
        $previousLimit = \ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '50');

        try {
            return $scrub();
        } finally {
            ini_set('pcre.backtrack_limit', false === $previousLimit ? '1000000' : $previousLimit);
        }
    }

    #[DataProvider('keySegmentRepeatedThousandsOfTimesCases')]
    public function test_a_key_segment_repeated_thousands_of_times_does_not_withhold_the_file(string $craftedLine): void
    {
        $output = $this->regexSecretScrubber->scrub(\sprintf("%s\npassword: hunter2hunter2", $craftedLine));

        self::assertSame(\sprintf("%s\npassword: \"***REDACTED:inline_assignment***\"", $craftedLine), $output);
    }

    /** @return iterable<string, array{0: string}> */
    public static function keySegmentRepeatedThousandsOfTimesCases(): iterable
    {
        yield 'a segment after an inline credential word' => ['secret'.str_repeat('_a', 8190).'x'];
        yield 'a glued qualifier of an environment key' => [' '.str_repeat('API', 8190).'='];
        yield 'a segment before an environment credential word' => [' '.str_repeat('A_', 24568).'='];
        yield 'a segment after an environment credential word' => [' SECRET'.str_repeat('_A', 8188).'='];
    }

    public function test_an_unquoted_value_of_thousands_of_words_is_redacted_whole(): void
    {
        $output = $this->regexSecretScrubber->scrub('password: abcd'.str_repeat(' a', 8188));

        self::assertSame('password: "***REDACTED:inline_assignment***"', $output);
    }

    #[DataProvider('repetitionsPastThePcreRecursionLimitCases')]
    #[RunInSeparateProcess]
    public function test_a_repetition_past_the_pcre_recursion_limit_does_not_withhold_the_file_without_the_jit(string $input, string $expected): void
    {
        ini_set('pcre.jit', '0');

        self::assertSame($expected, $this->regexSecretScrubber->scrub($input));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function repetitionsPastThePcreRecursionLimitCases(): iterable
    {
        foreach ([
            'a segment after an inline credential word' => 'secret'.str_repeat('_a', 49998).'x',
            'a glued qualifier of an environment key' => ' '.str_repeat('API', 27776).'=',
            'a segment before an environment credential word' => ' '.str_repeat('A_', 24998).'=',
            'a segment after an environment credential word' => ' SECRET'.str_repeat('_A', 23807).'=',
        ] as $name => $craftedLine) {
            yield $name => [\sprintf("%s\npassword: hunter2hunter2", $craftedLine), \sprintf("%s\npassword: \"***REDACTED:inline_assignment***\"", $craftedLine)];
        }

        yield 'a word of an unquoted value' => ['password: abcd'.str_repeat(' a', 49997), 'password: "***REDACTED:inline_assignment***"'];
    }

    public function test_half_a_megabyte_of_private_key_headers_is_scrubbed_in_linear_time(): void
    {
        $content = str_repeat('-----BEGIN PRIVATE KEY-----', 19418);

        self::assertLessThan(1.0, $this->secondsToScrubUnchanged($content));
    }

    #[DataProvider('quadraticWithoutTheJitCases')]
    #[RunInSeparateProcess]
    public function test_a_crafted_file_is_scrubbed_in_linear_time_without_the_jit(string $content): void
    {
        ini_set('pcre.jit', '0');

        self::assertLessThan(1.0, $this->secondsToScrubUnchanged($content));
    }

    /** @return iterable<string, array{0: string}> */
    public static function quadraticWithoutTheJitCases(): iterable
    {
        yield 'private key headers without an end marker' => [str_repeat('-----BEGIN PRIVATE KEY-----', 4855)];
        yield 'scheme characters with no scheme separator' => [str_repeat('a-', 65536).'@'];
        yield 'a private key header followed by blank lines' => ["-----BEGIN PRIVATE KEY-----\n".str_repeat("\n", 524288)];
        yield 'an xml argument whose body is never closed' => ['<argument key="password">'.str_repeat('a', 524288)];
        yield 'a block scalar header over blank lines' => ["secret: |\n".str_repeat("  \n", 170000)];
        yield 'credential key openings' => [str_repeat("('db_password', ", 32768)];
        yield 'credential setters without arguments' => [str_repeat('->setpassword', 40342)];
        yield 'pdo connections without a password' => [str_repeat('new PDO(a,b,', 43690)];
        yield 'password function openings' => [str_repeat('password_hash(', 37449)];
        yield 'constant keywords with no name' => [str_repeat('const ', 87381)];
        yield 'constants named like credentials with no value' => [str_repeat('const SECRET_KEY ', 30840)];
        yield 'closers after a credential key' => ['password: '.str_repeat(')', 524288)];
        yield 'placeholder openings after colons' => [str_repeat(': ***REDACTED:x', 34952)];
        yield 'dsn assignments holding no credential' => [str_repeat('MAILER_DSN=a://b?c=d ', 24966)];
        yield 'bearer words with no token' => [str_repeat('Bearer ', 74898)];
        yield 'fallback operators with no literal' => ['$password = $a'.str_repeat(' ?? $a', 90000)];
        yield 'credential keys followed by operands' => [str_repeat('password = $a ?: $b ?: $c ', 20000)];
        yield 'a fallback literal never closed' => ['$password = $a ?: "'.str_repeat('a', 524288)];
    }

    #[DataProvider('hostileContentWithTheJitCases')]
    public function test_a_crafted_file_is_scrubbed_in_linear_time_with_the_jit(string $content): void
    {
        self::assertLessThan(1.0, $this->secondsToScrubUnchanged($content));
    }

    /** @return iterable<string, array{0: string}> */
    public static function hostileContentWithTheJitCases(): iterable
    {
        yield 'a private key header followed by blank lines' => ["-----BEGIN PRIVATE KEY-----\n".str_repeat("\n", 524288)];
        yield 'an xml argument whose body is never closed' => ['<argument key="password">'.str_repeat('a', 524288)];
        yield 'a block scalar header over blank lines' => ["secret: |\n".str_repeat("  \n", 170000)];
        yield 'credential key openings' => [str_repeat("('db_password', ", 32768)];
        yield 'credential setters without arguments' => [str_repeat('->setpassword', 40342)];
        yield 'password function openings' => [str_repeat('password_hash(', 37449)];
        yield 'fallback operators with no literal' => ['$password = $a'.str_repeat(' ?? $a', 90000)];
        yield 'a fallback literal never closed' => ['$password = $a ?: "'.str_repeat('a', 524288)];
    }

    #[DataProvider('hostileContentRedactedCases')]
    public function test_a_crafted_file_is_redacted_in_linear_time_with_the_jit(string $content, string $expected): void
    {
        $this->assertRedactedInLinearTime($content, $expected);
    }

    #[DataProvider('hostileContentRedactedCases')]
    #[RunInSeparateProcess]
    public function test_a_crafted_file_is_redacted_in_linear_time_without_the_jit(string $content, string $expected): void
    {
        ini_set('pcre.jit', '0');

        $this->assertRedactedInLinearTime($content, $expected);
    }

    private function assertRedactedInLinearTime(string $content, string $expected): void
    {
        $startedAt = hrtime(true);

        $output = $this->regexSecretScrubber->scrub($content);

        self::assertLessThan(1.0, (hrtime(true) - $startedAt) / 1_000_000_000);
        self::assertSame(md5($expected), md5($output));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function hostileContentRedactedCases(): iterable
    {
        yield 'a pure function call opening on spaces' => ['password = md5('.str_repeat(' ', 524288), 'password = ***REDACTED:inline_assignment***'.str_repeat(' ', 524288)];
        yield 'an openai key of half a megabyte' => ['sk-'.str_repeat('a', 524288), '***REDACTED:openai_api_key***'];
        yield 'a block scalar of a hundred thousand lines' => ["secret: |\n".str_repeat("  x\n", 100000), "secret: |\n  ***REDACTED:block_scalar***".str_repeat("\n", 100000)];
        yield 'a private key cut after thirty thousand lines' => ["-----BEGIN PRIVATE KEY-----\n".str_repeat("MIIEowIBAAKCAQEAx\n", 30000), '***REDACTED:pem_private_key***'.str_repeat("\n", 30001)];
        yield 'an xml argument of half a megabyte' => ['<argument key="password">'.str_repeat('a', 524288).'</argument>', '<argument key="password">***REDACTED:xml_parameter***</argument>'];
        yield 'a fallback literal of half a megabyte' => ['$password = $a ?: "'.str_repeat('a', 524288).'";', '$password = $a ?: "***REDACTED:inline_assignment***";'];
        yield 'fallback literals line after line' => [str_repeat("\$password = \$a ?: 'abcd1234';\n", 12000), str_repeat("\$password = \$a ?: '***REDACTED:inline_assignment***';\n", 12000)];
        yield 'sixteen concatenations then a literal' => ['$password = $a'.str_repeat(' . $b', 16).' . "abcdefgh"', '$password = $a'.str_repeat(' . $b', 16).' . "abcdefgh"'];
    }

    #[RunInSeparateProcess]
    public function test_a_dsn_longer_than_a_url_can_be_is_redacted_in_linear_time_without_the_jit(): void
    {
        ini_set('pcre.jit', '0');
        $startedAt = hrtime(true);

        $output = $this->regexSecretScrubber->scrub('MAILER_DSN=a://b'.str_repeat('?c=d', 131070));

        self::assertLessThan(1.0, (hrtime(true) - $startedAt) / 1_000_000_000);
        self::assertSame('MAILER_DSN=***REDACTED:env_assignment***', $output);
    }

    public function test_a_dsn_of_exactly_the_longest_credential_free_length_is_left_readable_and_one_character_more_is_redacted(): void
    {
        $value = 'a://'.str_repeat('b', 256);

        self::assertSame('MAILER_DSN='.$value, $this->regexSecretScrubber->scrub('MAILER_DSN='.$value));
        self::assertSame('MAILER_DSN=***REDACTED:env_assignment***', $this->regexSecretScrubber->scrub('MAILER_DSN='.$value.'b'));
    }

    private function secondsToScrubUnchanged(string $content): float
    {
        $startedAt = hrtime(true);
        $output = $this->regexSecretScrubber->scrub($content);
        $elapsedSeconds = (hrtime(true) - $startedAt) / 1_000_000_000;

        self::assertSame(md5($content), md5($output));

        return $elapsedSeconds;
    }

    public function test_an_unterminated_quoted_value_full_of_backslashes_does_not_defeat_redaction_of_an_earlier_secret_in_the_same_file(): void
    {
        $payload = "password = \"SuperSecretPlaintext123!\"\nsecret = \"".str_repeat('\\', 40);

        $output = $this->regexSecretScrubber->scrub($payload);

        self::assertStringNotContainsString('SuperSecretPlaintext123!', $output);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_invalid_additional_pattern_throws_configuration_exception(): void
    {
        $this->expectException(SecretScrubberConfigurationException::class);
        $this->expectExceptionMessage('Invalid secret-scrubbing pattern /[unterminated/');

        new RegexSecretScrubber(additionalPatterns: ['/[unterminated/']);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_empty_additional_pattern_throws_configuration_exception(): void
    {
        $this->expectException(SecretScrubberConfigurationException::class);
        $this->expectExceptionMessage('empty pattern');

        new RegexSecretScrubber(additionalPatterns: ['']);
    }

    public function test_invalid_pattern_validation_suppresses_the_internal_pcre_warning(): void
    {
        error_clear_last();

        try {
            new RegexSecretScrubber(additionalPatterns: ['/[unterminated/']);
            self::fail('expected SecretScrubberConfigurationException');
        } catch (SecretScrubberConfigurationException) {
            self::assertNull(error_get_last());
        }
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->regexSecretScrubber = new RegexSecretScrubber();
    }

    private function assertParsesAsPhp(string $code): void
    {
        $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse($code);

        self::assertNotNull($nodes);
    }

    private function secretFragmentOf(string $input): string
    {
        if (str_contains($input, '=')) {
            $parts = explode('=', $input, 2);

            return $parts[1] ?? $input;
        }

        if (str_contains($input, ':')) {
            $parts = explode(':', $input, 2);

            return trim($parts[1] ?? $input, ' "\'');
        }

        return $input;
    }

    public function test_words_that_merely_start_with_pass_are_not_credentials(): void
    {
        $input = "PASSPORT_NUMBER=AB123456\nBYPASS_CACHE=true\nMAX_PW_LENGTH=8\nPASS_RATE=0.85\npassport: 'AB123456'\n";

        self::assertSame($input, $this->regexSecretScrubber->scrub($input));
    }
}
