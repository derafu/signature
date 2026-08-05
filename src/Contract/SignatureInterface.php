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
use Derafu\Xml\Contract\XmlDocumentInterface;
use LogicException;
use NoDiscard;

/**
 * Interface for the class that represents the electronic signature of an XML.
 */
interface SignatureInterface
{
    /**
     * Assigns the data of the signature node.
     *
     * @param array $data
     * @return static
     */
    public function setData(array $data): static;

    /**
     * Returns the data of the signature node.
     *
     * This is the data structure that allows creating the node as XML.
     *
     * @return array
     */
    #[NoDiscard()]
    public function getData(): array;

    /**
     * Adds the necessary data to the signature node to be able to calculate the
     * signature on these data.
     *
     * @param string $digestValue The calculated DigestValue.
     * @param CertificateInterface $certificate The digital certificate to assign.
     * @param string|null $reference The URI reference, which must include the
     * prefix "#"
     * @param string|null $signatureNamespace The namespace of the `Signature`
     * element.
     * @param bool $includeCertificateChain Whether to embed the certificate's
     * trust chain (if any) as additional `X509Certificate` nodes inside
     * `X509Data`. Disabled by default: most verifiers (e.g. the Chilean SII)
     * expect a single certificate and never need the chain, since they
     * validate the CA out of band. Enable it for verifiers that require or
     * accept the full chain per the XML-DSIG standard.
     * @return static
     */
    public function configureSignatureData(
        string $digestValue,
        CertificateInterface $certificate,
        ?string $reference = null,
        ?string $signatureNamespace = null,
        bool $includeCertificateChain = false
    ): static;

    /**
     * Assigns the `Xml` instance built with the data of the signature node.
     *
     * @param XmlDocumentInterface $xml
     * @return static
     */
    public function setXml(XmlDocumentInterface $xml): static;

    /**
     * Returns the `Xml` object that represents the `Signature` node.
     *
     * @return XmlDocumentInterface The `Xml` object with the data of the
     * `Signature` node.
     * @throws LogicException When the `Xml` of the node is not available.
     */
    #[NoDiscard()]
    public function getXml(): XmlDocumentInterface;

    /**
     * Returns the reference associated with the electronic signature, if it
     * exists.
     *
     * @return string|null The reference associated with the `Signature` node,
     * or `null` if it does not have.
     */
    #[NoDiscard()]
    public function getReference(): ?string;

    /**
     * Returns the DigestValue of the `Reference` node.
     *
     * @return string|null The DigestValue, or `null` if it is not defined.
     */
    #[NoDiscard()]
    public function getDigestValue(): ?string;

    /**
     * Returns the X509 certificate of the signer associated with the
     * `KeyInfo` node.
     *
     * This is always the signer's own ("leaf") certificate, never one of the
     * intermediate CA certificates of the trust chain. If `X509Data` has
     * more than one `X509Certificate` node (see `getX509CertificateChain()`),
     * this returns the first one, which is the signer's certificate.
     *
     * @return string|null The X509 certificate in base64, or `null` if it is
     * not defined.
     */
    #[NoDiscard()]
    public function getX509Certificate(): ?string;

    /**
     * Returns the intermediate CA certificates of the trust chain associated
     * with the `KeyInfo` node, if the signature embeds them.
     *
     * Most verifiers (e.g. the Chilean SII) do not need or expect this: they
     * validate the signer's CA out of band and only the certificate returned
     * by `getX509Certificate()` is present. This will be empty in that case.
     *
     * @return string[] The intermediate CA certificates in base64, in the
     * order they appear in `X509Data` (after the signer's certificate).
     * Empty if the signature does not embed a trust chain.
     */
    #[NoDiscard()]
    public function getX509CertificateChain(): array;

    /**
     * Sets the calculated signature value for the `SignedInfo` node.
     *
     * @param string $signatureValue The signature value in base64.
     * @return static
     */
    public function setSignatureValue(string $signatureValue): static;

    /**
     * Returns the calculated signature value for the `SignedInfo` node.
     *
     * @return string|null The calculated signature value in base64, or `null`
     * if it is not defined.
     */
    #[NoDiscard()]
    public function getSignatureValue(): ?string;
}
