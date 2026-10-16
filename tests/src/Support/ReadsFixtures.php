<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature\Support;

/**
 * Reads the fixtures of the tests.
 *
 * A fixture that can not be read is a failure of the test, not an empty text.
 */
trait ReadsFixtures
{
    /**
     * Reads a fixture.
     *
     * @param string $path Path of the file.
     * @return string Content of the file.
     */
    private function readFixture(string $path): string
    {
        $content = file_get_contents($path);
        if ($content === false) {
            $this->fail(sprintf('The fixture %s could not be read.', $path));
        }

        return $content;
    }
}
