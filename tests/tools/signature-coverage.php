<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

/**
 * Compares the characteristics of the electronic signatures of a set of XML
 * documents (for example, real documents that are not in the repository) with
 * the ones that the tests of the package exercise, to know which shapes of
 * signatures the tests do not cover.
 *
 * First the tests are run with the log of the documents enabled:
 *
 *     DERAFU_SIGNATURE_SHAPES_LOG=var/signature-shapes.log vendor/bin/phpunit
 *
 * Then, with the documents to compare:
 *
 *     php tests/tools/signature-coverage.php --log=var/signature-shapes.log <file-or-directory>...
 *
 * Options:
 *
 *   --log=<file>       Log of the documents of the tests (required).
 *   --fixtures=<dir>   Directory with the fixtures (default: `tests/fixtures`).
 *   --strict           Exit with an error if there are characteristics that the
 *                      tests do not exercise.
 *
 * The log has to be from a run of the tests with `xmlsec1` installed, otherwise
 * the ways that need it are not exercised.
 */

use Derafu\TestsSignature\Support\ShapeCoverage;
use Derafu\TestsSignature\Support\ShapeReport;

require __DIR__ . '/../../vendor/autoload.php';

$arguments = [];
foreach (is_array($_SERVER['argv'] ?? null) ? $_SERVER['argv'] : [] as $value) {
    if (is_string($value)) {
        $arguments[] = $value;
    }
}

$log = null;
$fixtures = __DIR__ . '/../fixtures';
$strict = false;
$paths = [];
foreach (array_slice($arguments, 1) as $argument) {
    if ($argument === '--help') {
        fwrite(STDERR, "See the comment at the start of this file.\n");
        exit(0);
    }
    if (str_starts_with($argument, '--log=')) {
        $log = substr($argument, strlen('--log='));
    } elseif (str_starts_with($argument, '--fixtures=')) {
        $fixtures = substr($argument, strlen('--fixtures='));
    } elseif ($argument === '--strict') {
        $strict = true;
    } else {
        $paths[] = $argument;
    }
}

if ($log === null || !is_file($log) || $paths === []) {
    fwrite(STDERR, "Usage: php tests/tools/signature-coverage.php --log=<file> [--fixtures=<dir>] [--strict] <file-or-directory>...\n");
    fwrite(STDERR, "The log is made running the tests with DERAFU_SIGNATURE_SHAPES_LOG=<file>.\n");
    exit(1);
}

$documents = ShapeCoverage::atomsOf(ShapeCoverage::files($paths));
$tests = ShapeCoverage::atomsOfTests($log, ShapeCoverage::files([$fixtures]));

echo ShapeReport::coverage($documents, $tests);

exit($strict && ShapeCoverage::missing($documents, $tests) !== [] ? 1 : 0);
