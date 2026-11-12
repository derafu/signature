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
 * Reads a value that is nested in the data of a signature.
 */
trait ReadsData
{
    /**
     * Gives the value that is at the path, or `null` if there is none.
     *
     */
    private function at(mixed $data, string ...$path): mixed
    {
        $value = $data;
        foreach ($path as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }

        return $value;
    }
}
