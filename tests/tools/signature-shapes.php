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
 * Shows the shapes of the electronic signatures of a set of XML documents.
 *
 * The shape is how the signature is written and what it covers (prefix,
 * nesting, algorithms, transforms, attribute of the signed element, signatures
 * inside the signed element, encoding and format), without the content of the
 * documents.
 *
 * Usage:
 *
 *     php tests/tools/signature-shapes.php <file-or-directory>...
 *
 * The directories are searched for `.xml` files in all their levels.
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
$paths = array_slice($arguments, 1);
if ($paths === [] || in_array('--help', $paths, true)) {
    fwrite(STDERR, "Usage: php tests/tools/signature-shapes.php <file-or-directory>...\n");
    exit($paths === [] ? 1 : 0);
}

echo ShapeReport::shapes(ShapeCoverage::files($paths));
