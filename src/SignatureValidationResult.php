<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature;

use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Contract\SignatureValidationResultInterface;
use Derafu\Signature\Exception\SignatureException;

/**
 * Class that represents the result of the validation of an XML signature node.
 *
 * Encapsulates the parsed signature node together with the validation error,
 * if any. Allows the caller to access the certificate data of the signer
 * regardless of whether the signature is valid or not.
 */
class SignatureValidationResult implements SignatureValidationResultInterface
{
    /**
     * @param SignatureInterface $signatureNode Parsed signature node.
     * @param SignatureException|null $error Validation error, or `null` if
     * the signature is valid.
     */
    public function __construct(
        private readonly SignatureInterface $signatureNode,
        private readonly ?SignatureException $error = null,
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function isValid(): bool
    {
        return $this->error === null;
    }

    /**
     * {@inheritDoc}
     */
    public function getSignatureNode(): SignatureInterface
    {
        return $this->signatureNode;
    }

    /**
     * {@inheritDoc}
     */
    public function getError(): ?SignatureException
    {
        return $this->error;
    }
}
