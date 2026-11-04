<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature\Contract;

use Derafu\Signature\Exception\SignatureException;
use JsonSerializable;
use NoDiscard;

/**
 * Interface for the class that represents the result of the validation of an
 * XML signature node.
 */
interface SignatureValidationResultInterface extends JsonSerializable
{
    /**
     * Returns `true` if the signature is valid (no validation error).
     *
     * @return bool `true` if the signature is valid (no validation error),
     * `false` otherwise.
     */
    #[NoDiscard()]
    public function isValid(): bool;

    /**
     * Returns the parsed signature node.
     *
     * @return SignatureInterface The parsed signature node.
     */
    #[NoDiscard()]
    public function getSignatureNode(): SignatureInterface;

    /**
     * Returns the validation error, or `null` if the signature is valid.
     *
     * @return SignatureException|null The validation error, or `null` if the
     * signature is valid.
     */
    #[NoDiscard()]
    public function getError(): ?SignatureException;

    /**
     * Returns the result as an array.
     *
     * @return array{valid: bool, error: array{message: string, code: int, errors: list<string>}|null, signature: array<string, mixed>}
     * Validity, the validation error (message, code and the errors that
     * explain it, without trace) and the data of the signature node.
     */
    #[NoDiscard()]
    public function toArray(): array;
}
