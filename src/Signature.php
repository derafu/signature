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

use Derafu\Array\ArrayPath;
use Derafu\Array\ArrayReader;
use Derafu\Certificate\Certificate;
use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Translation\Exception\Core\TranslatableLogicException as LogicException;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException as InvalidArgumentException;
use Derafu\Xml\Contract\XmlDocumentInterface;

/**
 * Class that represents the `Signature` node in an XML digitally signed using
 * the XML digital signature standard (XML DSIG).
 */
final class Signature implements SignatureInterface
{
    /**
     * XML document that represents the electronic signature node.
     *
     * @var XmlDocumentInterface
     */
    private XmlDocumentInterface $xml;

    /**
     * Namespace of the elements of the XML signature.
     */
    private const string NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Path in the data to the certificate (or the list of certificates, when
     * the trust chain is included).
     *
     * @var non-empty-list<string>
     */
    private const array X509_CERTIFICATE_PATH = ['Signature', 'KeyInfo', 'X509Data', 'X509Certificate'];

    /**
     * Data of the signature node.
     *
     * By default, the data is left empty and will be completed later either by
     * assigning the data or by loading a new XML with the data.
     *
     * @var array<int|string, mixed>
     */
    private array $data = [
        // Root node is Signature.
        // This is the node that will be included in the signed XML.
        'Signature' => [
            '@attributes' => [
                'xmlns' => self::NAMESPACE,
            ],
            // Data that will be signed. The most important tag here is the
            // "DigestValue" that contains a "summary" (digest) of the C14N of
            // the reference node.
            'SignedInfo' => [
                '@attributes' => [
                    'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
                ],
                'CanonicalizationMethod' => [
                    '@attributes' => [
                        'Algorithm' => 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
                    ],
                ],
                'SignatureMethod' => [
                    '@attributes' => [
                        'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                    ],
                ],
                'Reference' => [
                    '@attributes' => [
                        // Indicates which is the reference node, it must have a
                        // "#" prefix. If it is empty, it is understood that the
                        // entire XML is to be signed.
                        'URI' => '', // Optional.
                    ],
                    'Transforms' => [
                        'Transform' => [
                            '@attributes' => [
                                'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                            ],
                        ],
                    ],
                    'DigestMethod' => [
                        '@attributes' => [
                            'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1',
                        ],
                    ],
                    'DigestValue' => '', // Required.
                ],
            ],
            // Signature of the C14N of the `SignedInfo` node.
            // It is added after building the C14N of the SignedInfo and signing.
            'SignatureValue' => '', // Required.
            // Public key information for later validation of the electronic
            // signature.
            'KeyInfo' => [
                'KeyValue' => [
                    'RSAKeyValue' => [
                        'Modulus' => '', // Required.
                        'Exponent' => '', // Required.
                    ],
                ],
                'X509Data' => [
                    'X509Certificate' => '', // Required.
                ],
            ],
        ],
    ];

    /**
     * {@inheritDoc}
     */
    public function setData(array $data): static
    {
        // Assign the data.
        $this->data = $data;

        // Invalidate the XML of the signature node.
        $this->invalidateXml();

        // Return instance for chaining.
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * {@inheritDoc}
     */
    public function configureSignatureData(
        string $digestValue,
        CertificateInterface $certificate,
        ?string $reference = null,
        ?string $signatureNamespace = null,
        bool $includeCertificateChain = false,
        ?string $signaturePrefix = null
    ): static {
        if ($signaturePrefix !== null) {
            $this->setSignaturePrefix($signaturePrefix);
        }

        $instance = $this
            ->setReference($reference)
            ->setDigestValue($digestValue)
            ->setCertificate($certificate, $includeCertificateChain)
        ;

        if ($signatureNamespace !== null) {
            $instance->setSignatureNamespace($signatureNamespace);
        }

        return $instance;
    }

    /**
     * Sets the algorithm with which the `SignedInfo` is canonicalized.
     *
     * @param string $algorithm URI of the algorithm.
     * @return static The current instance for method chaining.
     */
    public function setCanonicalizationMethod(string $algorithm): static
    {
        $this->put(
            ['Signature', 'SignedInfo', 'CanonicalizationMethod', '@attributes', 'Algorithm'],
            $algorithm
        );
        $this->invalidateXml();

        return $this;
    }

    /**
     * Sets the algorithm with which the `SignedInfo` is signed.
     *
     * @param string $algorithm URI of the algorithm.
     * @return static The current instance for method chaining.
     */
    public function setSignatureMethod(string $algorithm): static
    {
        $this->put(
            ['Signature', 'SignedInfo', 'SignatureMethod', '@attributes', 'Algorithm'],
            $algorithm
        );
        $this->invalidateXml();

        return $this;
    }

    /**
     * Sets the `Id` of the `Signature` element, so it can be referenced.
     *
     * @return static The current instance for method chaining.
     */
    public function setSignatureId(string $id): static
    {
        $this->put(['Signature', '@attributes', 'Id'], $id);
        $this->invalidateXml();

        return $this;
    }

    /**
     * Sets the `Id` of the `SignatureValue` element, so it can be referenced
     * (a countersignature signs the value of another signature).
     *
     * @return static The current instance for method chaining.
     */
    public function setSignatureValueId(string $id): static
    {
        $path = ['Signature', 'SignatureValue'];
        $current = $this->get($path);
        $value = is_array($current) ? ($current['@value'] ?? '') : $current;
        $this->put($path, ['@attributes' => ['Id' => $id], '@value' => $value]);
        $this->invalidateXml();

        return $this;
    }

    /**
     * Sets the references of the signature, in the `SignedInfo`.
     *
     * @param list<array{uri: string, id: string|null, type: string|null, digestAlgorithm: string, digestValue: string, transforms: list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}>}> $references
     * For each reference: its `URI`, its `Id` and `Type`, the URI of the
     * digest algorithm, the digest and its transforms (the URI of the algorithm
     * and, for XPath, the expression with the namespaces of its prefixes).
     * @return static The current instance for method chaining.
     */
    public function setReferences(array $references): static
    {
        $nodes = [];
        foreach ($references as $reference) {
            $attributes = ['URI' => $reference['uri']];
            if ($reference['id'] !== null) {
                $attributes['Id'] = $reference['id'];
            }
            if ($reference['type'] !== null) {
                $attributes['Type'] = $reference['type'];
            }
            $node = ['@attributes' => $attributes];

            $transforms = [];
            foreach ($reference['transforms'] as $transform) {
                $item = ['@attributes' => ['Algorithm' => $transform['algorithm']]];
                if ($transform['expression'] !== null) {
                    $declarations = [];
                    foreach ($transform['namespaces'] as $prefix => $namespace) {
                        $declarations['xmlns:' . $prefix] = $namespace;
                    }
                    $item['XPath'] = ['@attributes' => $declarations, '@value' => $transform['expression']];
                }
                $transforms[] = $item;
            }
            if ($transforms !== []) {
                $node['Transforms'] = ['Transform' => count($transforms) === 1 ? $transforms[0] : $transforms];
            }
            $node['DigestMethod'] = ['@attributes' => ['Algorithm' => $reference['digestAlgorithm']]];
            $node['DigestValue'] = $reference['digestValue'];

            $prefix = $this->getSignaturePrefix();
            $nodes[] = $prefix === null ? $node : $this->renameElements($node, $prefix);
        }

        $this->put(
            ['Signature', 'SignedInfo', 'Reference'],
            count($nodes) === 1 ? $nodes[0] : $nodes
        );
        $this->invalidateXml();

        return $this;
    }

    /**
     * Sets the `Object` elements of the signature, after its `KeyInfo`.
     *
     * The content of each object is not an array of data but XML: it is given
     * as a text that the one that writes the signature replaces with the XML
     * (`$content`, that must not appear in the XML).
     *
     * @param list<array{id: string|null, mimeType: string|null, encoding: string|null, content: string}> $objects
     * @return static The current instance for method chaining.
     */
    public function setObjects(array $objects): static
    {
        $nodes = [];
        foreach ($objects as $object) {
            $attributes = [];
            if ($object['id'] !== null) {
                $attributes['Id'] = $object['id'];
            }
            if ($object['mimeType'] !== null) {
                $attributes['MimeType'] = $object['mimeType'];
            }
            if ($object['encoding'] !== null) {
                $attributes['Encoding'] = $object['encoding'];
            }
            $nodes[] = ['@attributes' => $attributes, '@value' => $object['content']];
        }

        $prefix = $this->getSignaturePrefix();
        $this->put(
            ['Signature', $prefix === null ? 'Object' : $prefix . ':Object'],
            count($nodes) === 1 ? $nodes[0] : $nodes
        );
        $this->invalidateXml();

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function setXml(XmlDocumentInterface $xml): static
    {
        $this->xml = $xml;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getXml(): XmlDocumentInterface
    {
        // If the instance has not been assigned previously, an exception is
        // thrown.
        if (!isset($this->xml)) {
            throw new LogicException(
                'The Xml instance is not available in Signature.'
            );
        }

        return $this->xml;
    }

    /**
     * {@inheritDoc}
     */
    public function getReference(): ?string
    {
        $uri = $this->getText(['Signature', 'SignedInfo', 'Reference', '@attributes', 'URI']);

        return $uri !== null ? ltrim($uri, '#') : null;
    }

    /**
     * {@inheritDoc}
     */
    public function getSignatureMethod(): ?string
    {
        return $this->getText(['Signature', 'SignedInfo', 'SignatureMethod', '@attributes', 'Algorithm']);
    }

    /**
     * {@inheritDoc}
     */
    public function getReferences(): array
    {
        $references = $this->get(['Signature', 'SignedInfo', 'Reference']);
        if (!is_array($references)) {
            return [];
        }

        $result = [];
        foreach (array_is_list($references) ? $references : [$references] as $reference) {
            if (!is_array($reference)) {
                continue;
            }

            $transforms = ArrayPath::get($reference, $this->resolvePath(['Transforms', 'Transform'], $reference));
            $algorithms = [];
            foreach (is_array($transforms) && array_is_list($transforms) ? $transforms : [$transforms] as $transform) {
                $attributes = is_array($transform) ? ($transform['@attributes'] ?? null) : null;
                $algorithm = is_array($attributes) ? ($attributes['Algorithm'] ?? null) : null;
                if (is_string($algorithm)) {
                    $algorithms[] = $algorithm;
                }
            }

            $result[] = [
                'uri' => $this->readText($reference, ['@attributes', 'URI']),
                'digestMethod' => $this->readText($reference, ['DigestMethod', '@attributes', 'Algorithm']),
                'digestValue' => $this->readText($reference, ['DigestValue']),
                'transforms' => $algorithms,
            ];
        }

        return $result;
    }

    /**
     * {@inheritDoc}
     */
    public function getDigestValue(): ?string
    {
        return $this->getText(['Signature', 'SignedInfo', 'Reference', 'DigestValue']);
    }

    /**
     * {@inheritDoc}
     */
    public function getX509Certificate(): ?string
    {
        $x509 = $this->unwrap($this->get(self::X509_CERTIFICATE_PATH));

        // With a trust chain there are several certificates: the first one is
        // the one of the signer.
        if (is_array($x509)) {
            $x509 = $this->unwrap($x509[0] ?? null);
        }

        return is_string($x509) && $x509 !== '' && $x509 !== '0' ? $x509 : null;
    }

    /**
     * {@inheritDoc}
     */
    public function getX509CertificateChain(): array
    {
        $x509 = $this->unwrap($this->get(self::X509_CERTIFICATE_PATH));

        if (!is_array($x509)) {
            return [];
        }

        return array_values(array_filter(
            array_map($this->unwrap(...), array_slice($x509, 1)),
            is_string(...)
        ));
    }

    /**
     * {@inheritDoc}
     */
    public function setSignatureValue(string $signatureValue): static
    {
        // Assign the electronic signature of the `SignedInfo` node. If the node
        // has attributes (its `Id`), they are kept.
        $path = ['Signature', 'SignatureValue'];
        $this->put(
            is_array($this->get($path)) ? [...$path, '@value'] : $path,
            wordwrap($signatureValue, 64, "\n", true)
        );

        // Invalidate the XML of the signature node.
        $this->invalidateXml();

        // Return instance for chaining.
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getSignatureValue(): ?string
    {
        return $this->getText(['Signature', 'SignatureValue']);
    }

    /**
     * Sets the namespace of the `Signature` element.
     *
     * By default the standard XML DSIG namespace is used. Some systems (e.g.
     * the Chilean SII for boleta books) require a different namespace on the
     * `Signature` element. Setting it here ensures that the C14N of
     * `SignedInfo` is computed with the correct namespace both at signing and
     * at validation time, keeping the signature mathematically consistent.
     *
     * @param string $namespace The namespace URI to use.
     * @return static The current instance for method chaining.
     */
    private function setSignatureNamespace(string $namespace): static
    {
        $prefix = $this->getSignaturePrefix();
        $this->put(
            ['Signature', '@attributes', $prefix === null ? 'xmlns' : 'xmlns:' . $prefix],
            $namespace
        );

        $this->invalidateXml();

        return $this;
    }

    /**
     * Sets the URI reference for the electronic signature.
     *
     * @param string|null $reference The URI reference, which must include the
     * prefix "#".
     * @return static The current instance for method chaining.
     */
    private function setReference(?string $reference = null): static
    {
        // Assign the URI reference (or empty if the entire XML is signed).
        $uri = $reference ? ('#' . ltrim($reference, '#')) : '';
        $this->put(['Signature', 'SignedInfo', 'Reference', '@attributes', 'URI'], $uri);

        // Assign the transformation algorithm when obtaining the C14N.
        $this->put(
            ['Signature', 'SignedInfo', 'Reference', 'Transforms', 'Transform', '@attributes', 'Algorithm'],
            $reference
                ? 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
                : 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
        );

        // Invalidate the XML of the signature node.
        $this->invalidateXml();

        // Return instance for chaining.
        return $this;
    }

    /**
     * Sets the DigestValue of the `Reference` node.
     *
     * @param string $digestValue The calculated DigestValue.
     * @return static The current instance for method chaining.
     */
    private function setDigestValue(string $digestValue): static
    {
        // Assign the digest value.
        $this->put(['Signature', 'SignedInfo', 'Reference', 'DigestValue'], $digestValue);

        // Invalidate the XML of the signature node.
        $this->invalidateXml();

        // Return instance for chaining.
        return $this;
    }

    /**
     * Assigns a digital certificate to the current instance and updates the
     * corresponding values in the `KeyInfo` node (module, exponent and
     * certificate in X509 format).
     *
     * @param CertificateInterface $certificate The digital certificate to assign.
     * @param bool $includeCertificateChain Whether to embed the certificate's
     * trust chain (if any) as additional `X509Certificate` nodes. See
     * `SignatureInterface::configureSignatureData()`.
     * @return static The current instance for method chaining.
     */
    private function setCertificate(
        CertificateInterface $certificate,
        bool $includeCertificateChain = false
    ): static {
        // Add module and exponent, which allow others to validate the XML
        // signature. Only an RSA key has them: with another kind of key
        // (elliptic curve, DSA) the `KeyInfo` has only the certificate, that
        // has the public key.
        if (ArrayReader::fromArray($certificate->getPublicKeyDetails())->getInt('type', OPENSSL_KEYTYPE_RSA) === OPENSSL_KEYTYPE_RSA) {
            $this->put(
                ['Signature', 'KeyInfo', 'KeyValue', 'RSAKeyValue', 'Modulus'],
                $certificate->getModulus()
            );
            $this->put(
                ['Signature', 'KeyInfo', 'KeyValue', 'RSAKeyValue', 'Exponent'],
                $certificate->getExponent()
            );
        } else {
            $this->removeKeyValue();
        }

        // Add the certificate. If the trust chain was requested and the
        // certificate has one, it is embedded as additional sibling
        // `X509Certificate` nodes, with the signer's certificate first.
        // Otherwise (the default), a single certificate is embedded, exactly
        // as before: this keeps the signature byte-identical for verifiers
        // that expect only one certificate, like the Chilean SII.
        $x509Certificates = [$certificate->getCertificate(true)];
        if ($includeCertificateChain) {
            array_push(
                $x509Certificates,
                ...$certificate->getCertificateChain(true)
            );
        }
        $this->put(
            self::X509_CERTIFICATE_PATH,
            count($x509Certificates) > 1 ? $x509Certificates : $x509Certificates[0]
        );

        // Invalidate the XML of the signature node.
        $this->invalidateXml();

        // Return instance for chaining.
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        $signedInfo = ['Signature', 'SignedInfo'];
        $reference = [...$signedInfo, 'Reference'];
        $rsaKeyValue = ['Signature', 'KeyInfo', 'KeyValue', 'RSAKeyValue'];

        return [
            'reference' => $this->getReference(),
            'canonicalizationMethod' => $this->getText([
                ...$signedInfo, 'CanonicalizationMethod', '@attributes', 'Algorithm',
            ]),
            'signatureMethod' => $this->getText([
                ...$signedInfo, 'SignatureMethod', '@attributes', 'Algorithm',
            ]),
            'digestMethod' => $this->getText([
                ...$reference, 'DigestMethod', '@attributes', 'Algorithm',
            ]),
            'digestValue' => $this->getDigestValue(),
            'signatureValue' => $this->getSignatureValue(),
            'modulus' => $this->getText([...$rsaKeyValue, 'Modulus']),
            'exponent' => $this->getText([...$rsaKeyValue, 'Exponent']),
            'certificate' => $this->getX509Certificate(),
            'certificateChain' => $this->getX509CertificateChain(),
            'signer' => $this->getSignerData(),
        ];
    }

    /**
     * {@inheritDoc}
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Returns the data of the signer's certificate, without the private key.
     *
     * @return array<string, mixed>|null `null` if the node has no certificate
     * or it can not be read.
     */
    private function getSignerData(): ?array
    {
        $x509 = $this->getX509Certificate();
        if ($x509 === null) {
            return null;
        }

        try {
            $data = (new Certificate($x509))->toArray();
        } catch (CertificateException) {
            return null;
        }

        unset($data['pkey']);

        return $data;
    }

    /**
     * Reads a value of the data that is text.
     *
     * @param non-empty-list<string> $path The keys that lead to the value.
     * @return string|null The text, or `null` if it is not in the data, it is
     * not text or it is empty.
     */
    private function getText(array $path): ?string
    {
        return $this->asText($this->get($path));
    }

    /**
     * Reads a text of a part of the data, with or without namespace prefix in
     * the names of the elements.
     *
     * @param array<int|string, mixed> $data The part of the data.
     * @param non-empty-list<string> $path The keys that lead to the value.
     * @return string|null The text, or `null` if it is not there.
     */
    private function readText(array $data, array $path): ?string
    {
        return $this->asText(ArrayPath::get($data, $this->resolvePath($path, $data)));
    }

    /**
     * Returns the text of an element that has attributes, which the decoder
     * gives as `['@attributes' => ..., '@value' => text]`. Any other value is
     * returned as it is.
     */
    private function unwrap(mixed $value): mixed
    {
        return is_array($value) && array_key_exists('@value', $value) ? $value['@value'] : $value;
    }

    /**
     * Returns the value if it is a text that is not empty.
     */
    private function asText(mixed $value): ?string
    {
        $value = $this->unwrap($value);

        return is_string($value) && $value !== '' && $value !== '0' ? $value : null;
    }

    /**
     * Returns the prefix of the namespace with which the elements of the
     * signature are named in the data (the `ds` of `ds:Signature`).
     *
     * @return string|null The prefix, or `null` if the elements have no prefix.
     */
    private function getSignaturePrefix(): ?string
    {
        $root = array_key_first($this->data);
        if (!is_string($root) || !str_contains($root, ':')) {
            return null;
        }

        return explode(':', $root, 2)[0];
    }

    /**
     * Names the elements of the signature with a namespace prefix (`ds:Signature`,
     * `ds:SignedInfo`, ...) and declares that prefix in the `Signature` element
     * in place of the default namespace.
     *
     * The data is rebuilt from its current names, so any previous prefix is
     * replaced.
     *
     * @param string $prefix The prefix, without the colon.
     * @return void
     * @throws InvalidArgumentException If the prefix is not valid.
     */
    private function setSignaturePrefix(string $prefix): void
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_.-]*$/', $prefix) !== 1
            || in_array(strtolower($prefix), ['xml', 'xmlns'], true)
        ) {
            throw new InvalidArgumentException([
                'The namespace prefix "{prefix}" of the signature is not valid.',
                'prefix' => $prefix,
            ]);
        }

        $current = $this->getSignaturePrefix();
        $data = $this->renameElements($this->data, $prefix);
        $root = array_key_first($data);
        $element = $root !== null ? $data[$root] : null;
        if (is_string($root) && is_array($element)) {
            $declaration = $current === null ? 'xmlns' : 'xmlns:' . $current;
            $attributes = is_array($element['@attributes'] ?? null) ? $element['@attributes'] : [];
            $namespace = $attributes[$declaration] ?? self::NAMESPACE;
            unset($attributes[$declaration]);
            $element['@attributes'] = ['xmlns:' . $prefix => $namespace] + $attributes;
            $data[$root] = $element;
        }
        $this->data = $data;

        $this->invalidateXml();
    }

    /**
     * Gives the elements of the data the same prefix, or removes it.
     *
     * @param array<int|string, mixed> $data Data of an element.
     * @param string $prefix The prefix that the elements will have.
     * @return array<int|string, mixed>
     */
    private function renameElements(array $data, string $prefix): array
    {
        $renamed = [];
        foreach ($data as $key => $value) {
            $isElement = is_string($key) && !str_starts_with($key, '@');
            if ($isElement) {
                $key = $prefix . ':' . $this->localName($key);
            }
            // The items of a list (integer keys) hold elements too.
            $isData = !is_string($key) || !str_starts_with($key, '@');
            $renamed[$key] = is_array($value) && $isData
                ? $this->renameElements($value, $prefix)
                : $value;
        }

        return $renamed;
    }

    /**
     * Returns the name of an element without its namespace prefix.
     */
    private function localName(string $name): string
    {
        $position = strrpos($name, ':');

        return $position === false ? $name : substr($name, $position + 1);
    }

    /**
     * Resolves a path of the data to the keys that really exist in it.
     *
     * The names of the elements are searched without their namespace prefix,
     * since `Signature` and `ds:Signature` are the same element of the XML
     * signature. A name that is not found is kept as it is, so that setting a
     * value creates it with the requested name.
     *
     * @param non-empty-list<string> $path The names of the elements, as
     * `Signature` or `SignedInfo`, and the keys of the attributes.
     * @param array<int|string, mixed>|null $base Data where the path is
     * resolved, by default the data of the signature node.
     * @return non-empty-list<string> The keys of the data.
     */
    private function resolvePath(array $path, ?array $base = null): array
    {
        $resolved = [];
        $level = $base ?? $this->data;
        $previous = null;
        foreach ($path as $name) {
            $key = $name;
            if (is_array($level)
                && $previous !== '@attributes'
                && !array_key_exists($name, $level)
            ) {
                foreach (array_keys($level) as $candidate) {
                    if (is_string($candidate)
                        && !str_starts_with($candidate, '@')
                        && $this->localName($candidate) === $name
                    ) {
                        $key = $candidate;
                        break;
                    }
                }
            }
            $level = is_array($level) ? ($level[$key] ?? null) : null;
            $resolved[] = $key;
            $previous = $key;
        }

        return $resolved;
    }

    /**
     * Reads a value of the data, with or without namespace prefix in the
     * names of the elements.
     *
     * @param non-empty-list<string> $path
     */
    private function get(array $path): mixed
    {
        return ArrayPath::get($this->data, $this->resolvePath($path));
    }

    /**
     * Sets a value of the data, with or without namespace prefix in the names
     * of the elements.
     *
     * @param non-empty-list<string> $path
     */
    private function put(array $path, mixed $value): void
    {
        $this->data = ArrayPath::set($this->data, $this->resolvePath($path), $value);
    }

    /**
     * Removes the `KeyValue` of the `KeyInfo`.
     */
    private function removeKeyValue(): void
    {
        $path = ['Signature', 'KeyInfo'];
        $keyInfo = $this->get($path);
        if (!is_array($keyInfo)) {
            return;
        }

        foreach (array_keys($keyInfo) as $key) {
            if (is_string($key) && $this->localName($key) === 'KeyValue') {
                unset($keyInfo[$key]);
            }
        }
        $this->put($path, $keyInfo);
    }

    /**
     * Invalidates the Xml associated with the signature node.
     *
     * This method is used when assigning data to the node, since the Xml
     * should be regenerated (this is done outside and must be assigned again).
     *
     * The invalidation is done by applying `unset()` to the Xml.
     *
     * @return void
     */
    private function invalidateXml(): void
    {
        unset($this->xml);
    }
}
