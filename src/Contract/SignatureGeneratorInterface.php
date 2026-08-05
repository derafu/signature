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

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Exception\XmlException;
use NoDiscard;

/**
 * Interface for the class that handles the generation of digital signatures.
 */
interface SignatureGeneratorInterface
{
    /**
     * Sign the provided data using a digital certificate.
     *
     * @param string $data Data to be signed.
     * @param string $privateKey Private key to be used for signing.
     * @param string|int $signatureAlgorithm Algorithm to be used for signing
     * (default SHA1).
     * @return string Digital signature in base64.
     */
    #[NoDiscard()]
    public function sign(
        string $data,
        string $privateKey,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): string;

    /**
     * Sign an XML document using RSA and SHA1.
     *
     * @param XmlDocumentInterface|string $xml XML document to be signed.
     * @param CertificateInterface $certificate Digital certificate to be used
     * for signing.
     * @param ?string $reference Reference to which the signature is made. If
     * not specified, the digest of the entire XML document will be signed.
     * @param ?string $signatureNamespace The namespace of the `Signature`
     * element.
     * @param bool $includeCertificateChain Whether to embed the certificate's
     * trust chain (if any) as additional `X509Certificate` nodes inside
     * `X509Data`. Disabled by default: most verifiers (e.g. the Chilean SII)
     * expect a single certificate and never need the chain, since they
     * validate the CA out of band. Enable it for verifiers that require or
     * accept the full chain per the XML-DSIG standard.
     * @return string String XML with the generated signature included in the
     * "Signature" tag at the end of the XML (last element within the root node).
     * @throws SignatureException If any problem occurs while signing.
     */
    #[NoDiscard()]
    public function signXml(
        XmlDocumentInterface|string $xml,
        CertificateInterface $certificate,
        ?string $reference = null,
        ?string $signatureNamespace = null,
        bool $includeCertificateChain = false
    ): string;

    /**
     * Generate the SHA1 ("DigestValue") of a node of the XML with a certain
     * reference. This can be used later to generate the XML signature.
     *
     * If no reference is specified, the "DigestValue" will be calculated over
     * the entire XML (root node).
     *
     * @param XmlDocumentInterface $doc XML document to be signed.
     * @param ?string $reference Reference to which the signature is made.
     * @return string Data of the XML that must be digested.
     * @throws XmlException If the reference is not found in the XML.
     */
    #[NoDiscard()]
    public function generateXmlDigestValue(
        XmlDocumentInterface $doc,
        ?string $reference = null
    ): string;
}
