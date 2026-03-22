<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature;

use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Exception\SignatureException;

/**
 * Resultado de la validación de un nodo de firma XML.
 *
 * Encapsula el nodo de firma parseado junto con el error de validación,
 * si lo hubiere. Permite al llamador acceder a los datos del certificado
 * firmante independientemente de si la firma es válida o no.
 */
class SignatureValidationResult
{
    /**
     * @param SignatureInterface $signatureNode Nodo de firma parseado.
     * @param SignatureException|null $error Excepción de validación, o `null`
     *   si la firma es válida.
     */
    public function __construct(
        private readonly SignatureInterface $signatureNode,
        private readonly ?SignatureException $error = null,
    ) {
    }

    /**
     * Retorna `true` si la firma es válida (no hubo error de validación).
     */
    public function isValid(): bool
    {
        return $this->error === null;
    }

    /**
     * Retorna el nodo de firma parseado.
     */
    public function getSignatureNode(): SignatureInterface
    {
        return $this->signatureNode;
    }

    /**
     * Retorna la excepción de validación, o `null` si la firma es válida.
     */
    public function getError(): ?SignatureException
    {
        return $this->error;
    }
}
