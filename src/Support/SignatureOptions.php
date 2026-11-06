<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature\Support;

use Derafu\Config\Contract\OptionsInterface;
use Derafu\Config\Options;
use Derafu\Signature\Contract\ResourceResolverInterface;
use Derafu\Signature\Exception\SignatureException;
use DOMDocument;
use Symfony\Component\OptionsResolver\Exception\ExceptionInterface as OptionsResolverException;
use Symfony\Component\OptionsResolver\Options as ResolverOptions;

/**
 * Options of a signature, resolved with their schema.
 *
 * They are valid only for the signature that they are given to: the options
 * that are not given have the default value, and nothing is kept for the next
 * signature. Every default is what the signature did before the option
 * existed.
 */
final class SignatureOptions
{
    private const string PREFIX_PATTERN = '/^[A-Za-z_][A-Za-z0-9_.-]*$/';

    /**
     * @param list<array{uri: string, id: string|null, type: string|null, digest: string, transforms: list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}>}>|null $references
     * @param array{xpath: string, namespaces: array<string, string>, position: string}|null $location
     * @param list<array{xml: string, id: string|null, mimeType: string|null, encoding: string|null}> $objects
     */
    private function __construct(
        public readonly ?string $reference,
        public readonly ?string $signatureNamespace,
        public readonly bool $includeCertificateChain,
        public readonly ?string $signaturePrefix,
        public readonly ?string $signatureId,
        public readonly ?string $signatureValueId,
        public readonly ?array $location,
        public readonly ?array $references,
        public readonly string $digestAlgorithm,
        public readonly string $signatureAlgorithm,
        public readonly string $canonicalizationMethod,
        public readonly array $objects,
        public readonly ?ResourceResolverInterface $resourceResolver,
    ) {
    }

    /**
     * Resolves the options of a signature.
     *
     * @param array<array-key, mixed>|OptionsInterface $options
     * @param bool $detached Whether the signature is detached (it is not in a
     * document): it has to say what it signs, with `references`, and it has no
     * document where to be placed.
     * @throws SignatureException If an option is not valid.
     */
    public static function resolve(array|OptionsInterface $options, bool $detached = false): self
    {
        $reader = self::options($options, self::schema())->getReader();

        $references = $reader->getArray('references');
        $location = $reader->getArray('signature_location');
        $objects = $reader->requireArray('objects');
        $resolver = $reader->getObject('resource_resolver', ResourceResolverInterface::class);

        // The normalizers give the shape of these options: it is the one that
        // the docblock of the constructor says.
        /** @var list<array{uri: string, id: string|null, type: string|null, digest: string, transforms: list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}>}>|null $references */
        /** @var array{xpath: string, namespaces: array<string, string>, position: string}|null $location */
        /** @var list<array{xml: string, id: string|null, mimeType: string|null, encoding: string|null}> $objects */
        $settings = new self(
            reference: $reader->getString('reference'),
            signatureNamespace: $reader->getString('signature_namespace'),
            includeCertificateChain: $reader->requireBool('include_certificate_chain'),
            signaturePrefix: $reader->getString('signature_prefix'),
            signatureId: $reader->getString('signature_id'),
            signatureValueId: $reader->getString('signature_value_id'),
            location: $location,
            references: $references,
            digestAlgorithm: $reader->requireString('digest_algorithm'),
            signatureAlgorithm: $reader->requireString('signature_algorithm'),
            canonicalizationMethod: $reader->requireString('canonicalization_method'),
            objects: $objects,
            resourceResolver: $resolver instanceof ResourceResolverInterface ? $resolver : null,
        );

        $settings->assertConsistent($detached);

        return $settings;
    }

    /**
     * Resolves the options of the validation of a signature.
     *
     * @param array<array-key, mixed>|OptionsInterface $options
     * @throws SignatureException If an option is not valid.
     */
    public static function resolveResolver(array|OptionsInterface $options): ?ResourceResolverInterface
    {
        $resolver = self::options($options, [
            'resource_resolver' => ['types' => [ResourceResolverInterface::class, 'null'], 'default' => null],
        ])->getReader()->getObject('resource_resolver', ResourceResolverInterface::class);

        return $resolver instanceof ResourceResolverInterface ? $resolver : null;
    }

    /**
     * Resolves the options with a schema, without keeping them.
     *
     * @param array<array-key, mixed>|OptionsInterface $options
     * @param array<string, array<string, mixed>> $schema
     * @throws SignatureException If an option is not valid.
     */
    private static function options(array|OptionsInterface $options, array $schema): OptionsInterface
    {
        try {
            return new Options($options, $schema);
        } catch (OptionsResolverException $e) {
            throw self::invalid($e->getMessage(), $e);
        }
    }

    /**
     * Creates the exception for an option that is not valid.
     *
     * @param string $detail What is not valid.
     */
    private static function invalid(string $detail, ?OptionsResolverException $previous = null): SignatureException
    {
        return new SignatureException(
            [
                'The options of the signature are not valid: {detail}',
                'detail' => $detail,
            ],
            previous: $previous
        );
    }

    /**
     * Checks the options that depend on each other, and on where the signature
     * is.
     *
     * @throws SignatureException If the options are not valid together.
     */
    private function assertConsistent(bool $detached): void
    {
        $detail = null;
        if ($detached && $this->references === null) {
            $detail = 'a detached signature needs the option "references", to say what it signs.';
        } elseif ($detached && $this->location !== null) {
            $detail = 'a detached signature is not placed in a document, so it has no "signature_location".';
        } else {
            foreach ($this->references ?? [] as $reference) {
                if (ReferenceData::isExternal($reference['uri']) && $this->resourceResolver === null) {
                    $detail = 'the reference "' . $reference['uri'] . '" is not in the document, so it needs the option "resource_resolver".';
                    break;
                }
            }
        }

        if ($detail !== null) {
            throw self::invalid($detail);
        }
    }

    /**
     * Schema of the options.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function schema(): array
    {
        return [
            // Reference to which the signature is made (`Id` of an element).
            'reference' => ['types' => ['string', 'null'], 'default' => null],
            'signature_namespace' => ['types' => ['string', 'null'], 'default' => null],
            'include_certificate_chain' => ['types' => 'bool', 'default' => false],
            'signature_prefix' => ['types' => ['string', 'null'], 'default' => null],
            'signature_id' => ['types' => ['string', 'null'], 'default' => null],
            'signature_value_id' => ['types' => ['string', 'null'], 'default' => null],
            'signature_location' => [
                'types' => ['array', 'null'],
                'default' => null,
                'normalizer' => self::normalizeLocation(...),
            ],
            'references' => [
                'types' => ['array', 'null'],
                'default' => null,
                'normalizer' => self::normalizeReferences(...),
            ],
            'digest_algorithm' => [
                'types' => 'string',
                'default' => 'sha1',
                'choices' => array_keys(Algorithms::DIGESTS),
            ],
            'signature_algorithm' => [
                'types' => 'string',
                'default' => 'rsa-sha1',
                'choices' => array_keys(Algorithms::SIGNATURES),
            ],
            'canonicalization_method' => [
                'types' => 'string',
                'default' => 'c14n',
                'choices' => ['c14n', 'exc_c14n'],
            ],
            'objects' => [
                'types' => 'array',
                'default' => [],
                'normalizer' => self::normalizeObjects(...),
            ],
            'resource_resolver' => ['types' => [ResourceResolverInterface::class, 'null'], 'default' => null],
        ];
    }

    /**
     * Normalizes the location of the signature.
     *
     * @return array{xpath: string, namespaces: array<string, string>, position: string}|null
     */
    private static function normalizeLocation(ResolverOptions $options, mixed $value): ?array
    {
        if ($value === null) {
            return null;
        }
        $location = self::requireMap($value, 'signature_location');
        self::assertKeys($location, ['xpath', 'namespaces', 'position'], 'signature_location');

        $xpath = $location['xpath'] ?? null;
        if (!is_string($xpath) || trim($xpath) === '') {
            throw self::invalid('"signature_location" needs an "xpath" with the element where the signature goes.');
        }

        $position = $location['position'] ?? 'last_child';
        if (!in_array($position, ['last_child', 'first_child', 'before', 'after'], true)) {
            throw self::invalid('The "position" of "signature_location" must be one of: last_child, first_child, before, after.');
        }

        return [
            'xpath' => $xpath,
            'namespaces' => self::namespaces($location['namespaces'] ?? [], 'signature_location'),
            'position' => $position,
        ];
    }

    /**
     * Normalizes the references of the signature, with the default transforms
     * and digest algorithm of each one.
     *
     * @return list<array{uri: string, id: string|null, type: string|null, digest: string, transforms: list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}>}>|null
     */
    private static function normalizeReferences(ResolverOptions $options, mixed $value): ?array
    {
        if ($value === null) {
            return null;
        }
        if ($options['reference'] !== null) {
            throw self::invalid('"reference" and "references" can not be given together: "reference" is the short way of one reference.');
        }
        if (!is_array($value) || $value === [] || !array_is_list($value)) {
            throw self::invalid('"references" must be a list with at least one reference.');
        }

        $references = [];
        foreach ($value as $index => $item) {
            $name = 'references[' . $index . ']';
            $reference = self::requireMap($item, $name);
            self::assertKeys($reference, ['uri', 'id', 'type', 'transforms', 'digest_algorithm'], $name);

            $uri = $reference['uri'] ?? '';
            if (!is_string($uri)) {
                throw self::invalid('The "uri" of ' . $name . ' must be a string.');
            }
            $digest = $reference['digest_algorithm'] ?? $options['digest_algorithm'];
            if (!is_string($digest) || !isset(Algorithms::DIGESTS[$digest])) {
                throw self::invalid('The "digest_algorithm" of ' . $name . ' is not a supported algorithm.');
            }

            // Without transforms: the whole document without the signature,
            // the element, or the octets of a resource that is not in the
            // document.
            $transforms = $reference['transforms'] ?? null;
            $items = $transforms === null
                ? match (true) {
                    ReferenceData::isExternal($uri) => [],
                    $uri === '' => ['enveloped'],
                    default => ['c14n'],
                }
            : $transforms;
            if (!is_array($items) || !array_is_list($items)) {
                throw self::invalid('The "transforms" of ' . $name . ' must be a list.');
            }

            $references[] = [
                'uri' => $uri,
                'id' => self::optionalString($reference['id'] ?? null, 'The "id" of ' . $name . ' must be a string.'),
                'type' => self::optionalString($reference['type'] ?? null, 'The "type" of ' . $name . ' must be a string.'),
                'digest' => $digest,
                'transforms' => array_map(
                    static fn (mixed $transform): array => self::normalizeTransform($transform, $name),
                    $items
                ),
            ];
        }

        return $references;
    }

    /**
     * Normalizes a transform of a reference.
     *
     * A transform is the name of one that has no parameters (`enveloped`,
     * `c14n`, `exc_c14n`), or an array with the XPath: `type` (`xpath`),
     * `expression` and the `namespaces` of the prefixes of the expression.
     *
     * The canonicalizations that keep the comments are not offered: the
     * references to an `Id` (`#Id`) and to the whole document leave the
     * comments out of the data, as XML Signature says, so a signature made with
     * them would not be valid for the implementations that follow it.
     *
     * @return array{algorithm: string, expression: string|null, namespaces: array<string, string>}
     */
    private static function normalizeTransform(mixed $transform, string $reference): array
    {
        if (is_string($transform)) {
            $algorithm = match ($transform) {
                'enveloped' => Algorithms::ENVELOPED,
                'c14n' => Algorithms::C14N,
                'exc_c14n' => Algorithms::EXC_C14N,
                default => throw self::invalid('A transform of ' . $reference . ' is not supported: use enveloped, c14n, exc_c14n or an xpath.'),
            };

            return ['algorithm' => $algorithm, 'expression' => null, 'namespaces' => []];
        }

        $map = self::requireMap($transform, 'a transform of ' . $reference);
        self::assertKeys($map, ['type', 'expression', 'namespaces'], 'a transform of ' . $reference);
        $expression = $map['expression'] ?? null;
        if (($map['type'] ?? null) !== 'xpath' || !is_string($expression) || trim($expression) === '') {
            throw self::invalid('A transform of ' . $reference . ' that is not a name must have the "type" xpath and its "expression".');
        }

        return [
            'algorithm' => Algorithms::XPATH,
            'expression' => $expression,
            'namespaces' => self::namespaces($map['namespaces'] ?? [], 'a transform of ' . $reference),
        ];
    }

    /**
     * Normalizes the objects of the signature.
     *
     * @return list<array{xml: string, id: string|null, mimeType: string|null, encoding: string|null}>
     */
    private static function normalizeObjects(ResolverOptions $options, mixed $value): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw self::invalid('"objects" must be a list.');
        }

        $objects = [];
        foreach ($value as $index => $item) {
            $name = 'objects[' . $index . ']';
            $object = self::requireMap($item, $name);
            self::assertKeys($object, ['xml', 'id', 'mime_type', 'encoding'], $name);

            $xml = $object['xml'] ?? null;
            if (!is_string($xml) || trim($xml) === '') {
                throw self::invalid('The "xml" of ' . $name . ' is the content of the object, and it must be XML.');
            }
            // A prefix that is not declared is an error that libxml recovers
            // from, so the errors are the ones that say if it is well formed.
            $dom = new DOMDocument();
            $internalErrors = libxml_use_internal_errors(true);
            libxml_clear_errors();
            $dom->loadXML('<object>' . $xml . '</object>');
            $wellFormed = array_filter(
                libxml_get_errors(),
                static fn ($error): bool => $error->level >= LIBXML_ERR_ERROR
            ) === [];
            libxml_clear_errors();
            libxml_use_internal_errors($internalErrors);
            if (!$wellFormed) {
                throw self::invalid('The "xml" of ' . $name . ' is not well formed XML (the prefixes it uses must be declared in it).');
            }

            $objects[] = [
                'xml' => $xml,
                'id' => self::optionalString($object['id'] ?? null, 'The "id" of ' . $name . ' must be a string.'),
                'mimeType' => self::optionalString($object['mime_type'] ?? null, 'The "mime_type" of ' . $name . ' must be a string.'),
                'encoding' => self::optionalString($object['encoding'] ?? null, 'The "encoding" of ' . $name . ' must be a string.'),
            ];
        }

        return $objects;
    }

    /**
     * Checks a map of prefixes and namespaces.
     *
     * @return array<string, string>
     */
    private static function namespaces(mixed $value, string $name): array
    {
        $map = self::requireMap($value, $name . ' "namespaces"');
        $namespaces = [];
        foreach ($map as $prefix => $namespace) {
            if (!is_string($prefix) || preg_match(self::PREFIX_PATTERN, $prefix) !== 1 || !is_string($namespace)) {
                throw self::invalid('The "namespaces" of ' . $name . ' must be a map of prefixes (names) to namespaces (strings).');
            }
            $namespaces[$prefix] = $namespace;
        }

        return $namespaces;
    }

    /**
     * Checks that a value is an array and gives it as a map.
     *
     * @return array<array-key, mixed>
     */
    private static function requireMap(mixed $value, string $name): array
    {
        if (!is_array($value)) {
            throw self::invalid('The value of ' . $name . ' must be an array.');
        }

        return $value;
    }

    /**
     * Checks that an array has only some keys.
     *
     * @param array<array-key, mixed> $value
     * @param list<string> $allowed
     */
    private static function assertKeys(array $value, array $allowed, string $name): void
    {
        $unknown = array_diff(array_map(strval(...), array_keys($value)), $allowed);
        if ($unknown !== []) {
            throw self::invalid(
                'The key "' . implode('", "', $unknown) . '" of ' . $name . ' is not valid; the valid ones are: ' . implode(', ', $allowed) . '.'
            );
        }
    }

    /**
     * Checks that a value is a string or `null`.
     */
    private static function optionalString(mixed $value, string $message): ?string
    {
        if ($value !== null && !is_string($value)) {
            throw self::invalid($message);
        }

        return $value;
    }
}
