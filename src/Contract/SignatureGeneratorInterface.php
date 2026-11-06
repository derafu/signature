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
use Derafu\Config\Contract\OptionsInterface;
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
     * Sign an XML document.
     *
     * With no options the document is signed as it always was: the signature
     * is the last child of the root element, it has one reference (the whole
     * document without the signature, or the element of `reference`), SHA-1
     * for the digest and RSA with SHA-1 for the signature.
     *
     * @param XmlDocumentInterface|string $xml XML document to be signed.
     * @param CertificateInterface $certificate Digital certificate to be used
     * for signing.
     * @param array<array-key, mixed>|OptionsInterface $options Options of the
     * signature. They are valid only for this signature (the generator does not
     * keep them), and the ones that are not given have the default value:
     * - `reference` (`string|null`, default `null`): Reference to which the
     *   signature is made. If it is not specified, the digest of the entire XML
     *   document will be signed.
     * - `references` (`list<array>|null`, default `null`): The references of the
     *   signature, when it has more than one or they need transforms. It can
     *   not be given with `reference`. Each one is an array with `uri` (default
     *   `''`, the whole document; `'#Id'` is an element; another one is a
     *   resource that is not in the document, that needs `resource_resolver`),
     *   `id`, `type`, `digest_algorithm` (default the `digest_algorithm`
     *   option) and `transforms`. The default transforms are the enveloped
     *   signature for the whole document, the canonicalization (`c14n`) for an
     *   element and none for a resource that is not in the document. A
     *   transform is `enveloped`, `c14n`, `exc_c14n`, or an array with `type` (`xpath`),
     *   `expression` and `namespaces` (prefix to namespace of the expression,
     *   that are declared in its element; `here()` is the element). The
     *   digests are made with the signature in its place in the document.
     * - `signature_location` (`array|null`, default `null`): Where the
     *   signature goes. If it is `null`, it is the last child of the root
     *   element. It is an array with `xpath` (the element, that must be only
     *   one), `namespaces` (prefix to namespace of the XPath) and `position`
     *   (`last_child` by default, `first_child`, `before` or `after` the
     *   element).
     * - `signature_namespace` (`string|null`, default `null`): The namespace of
     *   the `Signature` element.
     * - `signature_prefix` (`string|null`, default `null`): The prefix of the
     *   namespace with which the elements of the signature are named (`ds`
     *   gives `ds:Signature`, `ds:SignedInfo`, ...). If it is `null`, the
     *   elements have no prefix and the namespace is declared as the default
     *   one.
     * - `signature_id` and `signature_value_id` (`string|null`, default
     *   `null`): The `Id` of the `Signature` and of its `SignatureValue`, so
     *   another signature can reference them (a countersignature).
     * - `objects` (`list<array>`, default `[]`): The `Object` elements of the
     *   signature. Each one is an array with `xml` (its content, XML that
     *   declares its prefixes), `id`, `mime_type` and `encoding`. They can be
     *   referenced by their `id`, and they are signed.
     * - `digest_algorithm` (`string`, default `sha1`): `sha1`, `sha224`,
     *   `sha256`, `sha384` or `sha512`.
     * - `signature_algorithm` (`string`, default `rsa-sha1`): `rsa-sha1`,
     *   `rsa-sha224`, `rsa-sha256`, `rsa-sha384`, `rsa-sha512`, `ecdsa-sha1`,
     *   `ecdsa-sha224`, `ecdsa-sha256`, `ecdsa-sha384`, `ecdsa-sha512`,
     *   `dsa-sha1` or `dsa-sha256`. It must be the one of the type of key of
     *   the certificate.
     * - `canonicalization_method` (`string`, default `c14n`): `c14n` or
     *   `exc_c14n`, for the `SignedInfo`.
     * - `include_certificate_chain` (`bool`, default `false`): Whether to embed
     *   the certificate's trust chain (if any) as additional `X509Certificate`
     *   nodes inside `X509Data`. Disabled by default: most verifiers (e.g. the
     *   Chilean SII) expect a single certificate and never need the chain,
     *   since they validate the CA out of band. Enable it for verifiers that
     *   require or accept the full chain per the XML-DSIG standard.
     * - `resource_resolver` (`ResourceResolverInterface|null`, default
     *   `null`): Gives the data of the resources that the references point to
     *   and that are not in the document.
     * @return string String XML with the generated signature included in the
     * "Signature" tag, at the end of the root node if there is no
     * `signature_location`.
     * @throws SignatureException If an option is not valid, or any problem
     * occurs while signing.
     */
    #[NoDiscard()]
    public function signXml(
        XmlDocumentInterface|string $xml,
        CertificateInterface $certificate,
        array|OptionsInterface $options = []
    ): string;

    /**
     * Makes a signature that is not in a document (a detached signature).
     *
     * What it signs is what its `references` say: resources that are not in
     * the signature, that the `resource_resolver` gives, and the `Object`
     * elements of the signature. It takes the same options as `signXml()`, but
     * `references` is required and `reference` and `signature_location` are
     * not valid.
     *
     * @param CertificateInterface $certificate Digital certificate to be used
     * for signing.
     * @param array<array-key, mixed>|OptionsInterface $options Options of the
     * signature, see `signXml()`.
     * @return string The XML of the `Signature` element, as a document.
     * @throws SignatureException If an option is not valid, or any problem
     * occurs while signing.
     */
    #[NoDiscard()]
    public function signXmlDetached(
        CertificateInterface $certificate,
        array|OptionsInterface $options
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
