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

use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Xml\Contract\XmlDocumentInterface;
use NoDiscard;

/**
 * Interface for the class that handles the validation of electronic signatures.
 */
interface SignatureValidatorInterface
{
    /**
     * Validate the digital signature of data.
     *
     * @param string $data Data to be verified.
     * @param string $signature Digital signature of the data in base64.
     * @param string $publicKey Public key of the signature of the data.
     * @param string|int $signatureAlgorithm Algorithm used to sign
     * (default SHA1).
     * @return bool `true` if the signature is valid, `false` if it is invalid.
     * @throws SignatureException If there was an error while validating.
     */
    #[NoDiscard()]
    public function validate(
        string $data,
        string $signature,
        string $publicKey,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): bool;

    /**
     * Validate the validity of an XML signature using RSA and SHA1.
     *
     * Returns one `SignatureValidationResult` per signature node found. Each
     * result carries the parsed node (with certificate data) and the
     * validation error, if any. Callers must check `$result->isValid()` to
     * determine whether each signature passed.
     *
     * Only throws for structural problems (malformed XML, no signatures found).
     *
     * @param XmlDocumentInterface|string $xml XML string to be validated.
     * @return array<SignatureValidationResult> One result per signature node.
     * @throws SignatureException If the XML is malformed or has no signatures.
     */
    #[NoDiscard()]
    public function validateXml(XmlDocumentInterface|string $xml): array;

    /**
     * Creates the `Xml` instance of `Signature` from a string XML with the
     * signature node.
     *
     * @param string $xml String with the XML of the `Signature` node.
     */
    #[NoDiscard()]
    public function createSignatureNode(string $xml): SignatureInterface;

    /**
     * Validate the DigestValue of the signed data.
     *
     * @param XmlDocumentInterface|string $xml Document to be validated.
     * @param SignatureInterface $signatureNode Signature node to be validated.
     * @return void
     * @throws SignatureException If the DigestValue is invalid.
     */
    public function validateXmlDigestValue(
        XmlDocumentInterface|string $xml,
        SignatureInterface $signatureNode
    ): void;

    /**
     * Validate the signature of the `SignedInfo` node of the XML using the
     * X509 certificate.
     *
     * @param SignatureInterface $signatureNode Signature node to be validated.
     * @throws SignatureException If the XML signature is invalid.
     */
    public function validateXmlSignatureValue(
        SignatureInterface $signatureNode
    ): void;
}
