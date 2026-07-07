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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/** @internal not part of the BC promise — the enum *values* are the stable labels embedded in the `***REDACTED:<label>***` placeholder emitted by `RegexSecretScrubber`. Custom patterns registered through the scrubber constructor use synthetic `custom_<index>` labels and are intentionally outside this enum. */
enum SecretPatternLabel: string
{
    case AwsAccessKey = 'aws_access_key';
    case GithubToken = 'github_token';
    case StripeKey = 'stripe_key';
    case SlackToken = 'slack_token';
    case GoogleApiKey = 'google_api_key';
    case Jwt = 'jwt';
    case PemPrivateKey = 'pem_private_key';
    case EnvAssignment = 'env_assignment';
    case InlineAssignment = 'inline_assignment';
    case MultilineAssignment = 'multiline_assignment';
    case ConnectionUri = 'connection_uri';
}
