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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/** @internal not part of the BC promise — the enum *values* (`console`, `json`, `sarif`, `html`, `markdown`, `junit`) are part of the CLI contract, but the PHP enum itself is for internal use only. */
enum OutputFormat: string
{
    case Console = 'console';
    case Json = 'json';
    case Sarif = 'sarif';
    case Html = 'html';
    case Markdown = 'markdown';
    case Junit = 'junit';
}
