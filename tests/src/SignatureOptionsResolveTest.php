<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature;

use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use DOMDocument;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The options of a signature, resolved on their own: what they say when they are
 * not valid (the exact message), the types that they have and what is left in
 * libxml after reading the objects.
 */
#[CoversClass(SignatureOptions::class)]
#[CoversClass(SignatureException::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(ReferenceData::class)]
#[UsesClass(SignatureTranslationResourceProvider::class)]
final class SignatureOptionsResolveTest extends TestCase
{
    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function messageProvider(): array
    {
        return [
            'a digest algorithm of a reference that is not supported' => [
                ['references' => [['uri' => '#A', 'digest_algorithm' => 'md5']]],
                'The "digest_algorithm" of references[0] is not a supported algorithm.',
            ],
            'a transform that does not exist' => [
                ['references' => [['uri' => '#A', 'transforms' => ['base64']]]],
                'A transform of references[0] is not supported: use enveloped, c14n, exc_c14n or an xpath.',
            ],
            'a transform that is not a name and has no type' => [
                ['references' => [['uri' => '#A', 'transforms' => [['expression' => '/a']]]]],
                'A transform of references[0] that is not a name must have the "type" xpath and its "expression".',
            ],
            'an xpath without expression' => [
                ['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath']]]]],
                'A transform of references[0] that is not a name must have the "type" xpath and its "expression".',
            ],
            'an xpath with an expression of spaces' => [
                ['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath', 'expression' => ' ']]]]],
                'A transform of references[0] that is not a name must have the "type" xpath and its "expression".',
            ],
            'an xpath with namespaces that are not valid' => [
                ['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath', 'expression' => '/a', 'namespaces' => ['a b' => 'urn:a']]]]]],
                'The "namespaces" of a transform of references[0] must be a map of prefixes (names) to namespaces (strings).',
            ],
            'an xpath with namespaces that are not an array' => [
                ['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath', 'expression' => '/a', 'namespaces' => 'urn:a']]]]],
                'The value of a transform of references[0] "namespaces" must be an array.',
            ],
            'a location with namespaces that are not an array' => [
                ['signature_location' => ['xpath' => '/a', 'namespaces' => 'urn:a']],
                'The value of signature_location "namespaces" must be an array.',
            ],
            'a location with a key that does not exist' => [
                ['signature_location' => ['xpath' => '/a', 'where' => 1]],
                'The key "where" of signature_location is not valid; the valid ones are: xpath, namespaces, position.',
            ],
            'a location with two keys that do not exist' => [
                ['signature_location' => ['xpath' => '/a', 'a' => 1, 'b' => 2]],
                'The key "a", "b" of signature_location is not valid; the valid ones are: xpath, namespaces, position.',
            ],
            'an object that is not well formed' => [
                ['objects' => [['xml' => '<a>']]],
                'The "xml" of objects[0] is not well formed XML (the prefixes it uses must be declared in it).',
            ],
            'several resources that are not in the document' => [
                ['references' => [['uri' => 'http://a.example/one'], ['uri' => 'http://b.example/two']]],
                'the reference "http://a.example/one" is not in the document, so it needs the option "resource_resolver".',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('messageProvider')]
    public function testTheMessageOfAnOptionThatIsNotValidSaysExactlyWhatIsWrong(array $options, string $detail): void
    {
        try {
            SignatureOptions::resolve($options);
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertSame('The options of the signature are not valid: ' . $detail, $e->getMessage());
        }
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function typeProvider(): array
    {
        return [
            'reference' => [['reference' => 5]],
            'signature_namespace' => [['signature_namespace' => 5]],
            'include_certificate_chain' => [['include_certificate_chain' => 'yes']],
            'signature_prefix' => [['signature_prefix' => 5]],
            'signature_location' => [['signature_location' => 'x']],
            'references' => [['references' => 'x']],
            'objects' => [['objects' => 'x']],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('typeProvider')]
    public function testEachOptionHasTheTypeThatItNeeds(array $options): void
    {
        try {
            SignatureOptions::resolve($options);
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertStringContainsString('is expected to be of type', $e->getMessage());
            $this->assertStringContainsString((string) array_key_first($options), $e->getMessage());
        }
    }

    public function testTheOptionsThatAreGivenAreTheOnesOfTheSignature(): void
    {
        $settings = SignatureOptions::resolve([
            'reference' => 'Doc1',
            'signature_namespace' => 'urn:custom',
            'signature_prefix' => 'ds',
            'signature_id' => 'S1',
            'signature_value_id' => 'V1',
            'include_certificate_chain' => true,
        ]);

        $this->assertSame('Doc1', $settings->reference);
        $this->assertSame('urn:custom', $settings->signatureNamespace);
        $this->assertSame('ds', $settings->signaturePrefix);
        $this->assertSame('S1', $settings->signatureId);
        $this->assertSame('V1', $settings->signatureValueId);
        $this->assertTrue($settings->includeCertificateChain);
    }

    public function testTheNamespacesOfALocationAreAllKept(): void
    {
        $settings = SignatureOptions::resolve([
            'signature_location' => ['xpath' => '/a', 'namespaces' => ['a' => 'urn:a', 'b' => 'urn:b']],
        ]);

        $this->assertSame(['a' => 'urn:a', 'b' => 'urn:b'], $settings->location['namespaces'] ?? null);
    }

    /**
     * The XML of an object is well formed if libxml has no errors for it: the
     * warnings (a namespace that is a relative URI) are not errors.
     */
    public function testAnObjectWithAWarningOfLibxmlIsWellFormed(): void
    {
        $settings = SignatureOptions::resolve(['objects' => [['xml' => '<a xmlns="relative"/>']]]);

        $this->assertSame('<a xmlns="relative"/>', $settings->objects[0]['xml']);
    }

    public function testLibxmlIsAsItWasAfterReadingTheObjects(): void
    {
        $before = libxml_use_internal_errors(true);
        libxml_clear_errors();

        try {
            SignatureOptions::resolve(['objects' => [['xml' => '<a xmlns="relative"/>']]]);
            $this->assertSame([], libxml_get_errors());
            $this->assertTrue(libxml_use_internal_errors(true));

            libxml_use_internal_errors(false);
            SignatureOptions::resolve(['objects' => [['xml' => '<a/>']]]);
            $this->assertFalse(libxml_use_internal_errors(false));
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($before);
        }
    }

    /**
     * The errors that libxml had before are not errors of the object.
     */
    public function testAnErrorThatLibxmlHadBeforeIsNotAnErrorOfTheObject(): void
    {
        $before = libxml_use_internal_errors(true);
        libxml_clear_errors();

        try {
            (new DOMDocument())->loadXML('<bad');
            $this->assertNotEmpty(libxml_get_errors());

            $settings = SignatureOptions::resolve(['objects' => [['xml' => '<a/>']]]);

            $this->assertSame('<a/>', $settings->objects[0]['xml']);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($before);
        }
    }
}
