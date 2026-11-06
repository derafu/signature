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

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Config\Contract\OptionsInterface;
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Xml\Contract\XmlDocumentInterface;

/**
 * Generator of signatures that does the same as the one that it wraps and
 * records in the log of the documents what it signs.
 */
final class RecordingSignatureGenerator implements SignatureGeneratorInterface
{
    public function __construct(private readonly SignatureGeneratorInterface $generator)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function sign(
        string $data,
        string $privateKey,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): string {
        return $this->generator->sign($data, $privateKey, $signatureAlgorithm);
    }

    /**
     * {@inheritDoc}
     */
    public function signXml(
        XmlDocumentInterface|string $xml,
        CertificateInterface $certificate,
        array|OptionsInterface $options = []
    ): string {
        $signed = $this->generator->signXml($xml, $certificate, $options);
        // The signature that is made is the last one of the document.
        SignedDocumentsLog::record(
            SignedDocumentsLog::SIGNED_BY_LIBRARY,
            $signed,
            self::last(SignatureShape::signatureValues($signed))
        );

        return $signed;
    }

    /**
     * {@inheritDoc}
     */
    public function generateXmlDigestValue(
        XmlDocumentInterface $doc,
        ?string $reference = null
    ): string {
        return $this->generator->generateXmlDigestValue($doc, $reference);
    }

    /**
     * Gives the last of some values.
     *
     * @param list<string> $values
     */
    private static function last(array $values): ?string
    {
        return $values !== [] ? $values[array_key_last($values)] : null;
    }
}
