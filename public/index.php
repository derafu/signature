<?php

declare(strict_types=1);

/**
 * Derafu: Foundation - Base for Derafu's Projects.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.org>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

use Derafu\Http\Kernel;
use Derafu\Kernel\Environment;

require_once dirname(__DIR__) . '/app/bootstrap.php';

return fn (array $context): Kernel => new Kernel(new Environment(
    $context['APP_ENV'],
    (bool) $context['APP_DEBUG'],
    $context
));
