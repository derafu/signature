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

use Derafu\Config\Contract\OptionsInterface;
use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Contract\SignatureValidatorInterface;
use Derafu\Xml\Contract\XmlDocumentInterface;

/**
 * Validator of signatures that does the same as the one that it wraps and
 * records in the log of the documents what it validates.
 */
final class RecordingSignatureValidator implements SignatureValidatorInterface
{
    public function __construct(private readonly SignatureValidatorInterface $validator)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function validate(
        string $data,
        string $signature,
        string $certificate,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): bool {
        return $this->validator->validate($data, $signature, $certificate, $signatureAlgorithm);
    }

    /**
     * {@inheritDoc}
     */
    public function validateXml(XmlDocumentInterface|string $xml, array|OptionsInterface $options = []): array
    {
        SignedDocumentsLog::record(
            SignedDocumentsLog::VALIDATED_BY_LIBRARY,
            is_string($xml) ? $xml : $xml->saveXml()
        );

        return $this->validator->validateXml($xml, $options);
    }

    /**
     * {@inheritDoc}
     */
    public function createSignatureNode(string $xml): SignatureInterface
    {
        return $this->validator->createSignatureNode($xml);
    }

    /**
     * {@inheritDoc}
     */
    public function validateXmlDigestValue(
        XmlDocumentInterface|string $xml,
        SignatureInterface $signatureNode,
        array|OptionsInterface $options = []
    ): void {
        $this->validator->validateXmlDigestValue($xml, $signatureNode, $options);
    }

    /**
     * {@inheritDoc}
     */
    public function validateXmlSignatureValue(SignatureInterface $signatureNode): void
    {
        $this->validator->validateXmlSignatureValue($signatureNode);
    }
}
