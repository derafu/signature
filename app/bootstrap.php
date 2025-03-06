<?php

declare(strict_types=1);

/**
 * Derafu: Foundation - Base for Derafu's Projects.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.org>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

use Derafu\Http\Runtime;

if (
    true === (require_once dirname(__DIR__) . '/vendor/autoload.php')
    || empty($_SERVER['SCRIPT_FILENAME'])
) {
    return;
}

// Create the runtime.
$runtimeClass = $_SERVER['APP_RUNTIME'] ?? $_ENV['APP_RUNTIME'] ?? Runtime::class;
$runtime = new $runtimeClass();

// Get the handler.
$app = require $_SERVER['SCRIPT_FILENAME'];
if (!is_callable($app)) {
    throw new TypeError(sprintf(
        'Invalid return value: callable expected, "%s" returned from "%s".',
        get_debug_type($app),
        $_SERVER['SCRIPT_FILENAME']
    ));
}
$handler = $app($runtime->getApplicationContext());

// Run the application using the handler.
exit($runtime->run($handler));
