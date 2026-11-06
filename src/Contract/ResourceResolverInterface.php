<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature\Contract;

/**
 * Interface for the class that gives the data of the resources that a signature
 * references and that are not in the signed document (detached signatures).
 *
 * The package does not read files nor does network requests: whoever signs or
 * validates decides where the resources come from, and gives them with a
 * resolver.
 */
interface ResourceResolverInterface
{
    /**
     * Gives the data of the resource that a `Reference` points to.
     *
     * @param string $uri The `URI` attribute of the reference, as it is in the
     * signature.
     * @return string The content of the resource, as it is (its octets).
     */
    public function resolve(string $uri): string;
}
