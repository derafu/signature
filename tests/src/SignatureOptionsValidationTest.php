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

use Derafu\Config\Options;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\TestsSignature\Support\CreatesKeys;
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The options of the signature that are not valid are an error of the
 * signature, with what is wrong in the option.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
#[CoversClass(Algorithms::class)]
#[CoversClass(RawSignature::class)]
#[CoversClass(ReferenceData::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
#[CoversClass(SignatureOptions::class)]
final class SignatureOptionsValidationTest extends TestCase
{
    use CreatesKeys;
    use UsesXmlsec;

    protected function setUp(): void
    {
        $this->createService();
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidOptionsProvider(): array
    {
        return [
            'a signature id that is not a string' => [['signature_id' => 1], 'signature_id'],
            'a signature value id that is not a string' => [['signature_value_id' => []], 'signature_value_id'],
            'a digest algorithm that is not supported' => [['digest_algorithm' => 'md5'], 'digest_algorithm'],
            'a signature algorithm that is not supported' => [['signature_algorithm' => 'rsa-md5'], 'signature_algorithm'],
            'a canonicalization that is not supported' => [['canonicalization_method' => 'c14n_with_comments'], 'canonicalization_method'],
            'a resolver that is not one' => [['resource_resolver' => 1], 'resource_resolver'],
            'an option that does not exist' => [['digest' => 'sha1'], 'digest'],

            'a location that is not an array' => [['signature_location' => '/Root'], 'signature_location'],
            'a location without xpath' => [['signature_location' => ['position' => 'before']], 'needs an "xpath"'],
            'a location with an empty xpath' => [['signature_location' => ['xpath' => ' ']], 'needs an "xpath"'],
            'a location with an xpath that is not a string' => [['signature_location' => ['xpath' => 1]], 'needs an "xpath"'],
            'a location with a position that does not exist' => [['signature_location' => ['xpath' => '/a', 'position' => 'inside']], 'must be one of'],
            'a location with a key that does not exist' => [['signature_location' => ['xpath' => '/a', 'where' => 1]], 'The key "where" of signature_location is not valid'],
            'a location with namespaces that are not an array' => [['signature_location' => ['xpath' => '/a', 'namespaces' => 'urn:a']], 'must be an array'],
            'a location with a prefix that is not a name' => [['signature_location' => ['xpath' => '/a', 'namespaces' => ['1a' => 'urn:a']]], 'map of prefixes'],
            'a location with a prefix that is a position' => [['signature_location' => ['xpath' => '/a', 'namespaces' => ['urn:a']]], 'map of prefixes'],
            'a location with a namespace that is not a string' => [['signature_location' => ['xpath' => '/a', 'namespaces' => ['a' => 1]]], 'map of prefixes'],

            'reference and references together' => [['reference' => 'A', 'references' => [['uri' => '#A']]], 'can not be given together'],
            'references that are not a list' => [['references' => ['a' => ['uri' => '#A']]], 'must be a list'],
            'references that are empty' => [['references' => []], 'must be a list'],
            'a reference that is not an array' => [['references' => ['#A']], 'The value of references[0] must be an array'],
            'a reference with a key that does not exist' => [['references' => [['uri' => '#A', 'hash' => 'x']]], 'The key "hash" of references[0] is not valid'],
            'a reference with an uri that is not a string' => [['references' => [['uri' => 1]]], 'The "uri" of references[0] must be a string'],
            'a reference with an id that is not a string' => [['references' => [['uri' => '#A', 'id' => 1]]], 'The "id" of references[0] must be a string'],
            'a reference with a type that is not a string' => [['references' => [['uri' => '#A', 'type' => 1]]], 'The "type" of references[0] must be a string'],
            'a reference with a digest algorithm that is not supported' => [['references' => [['uri' => '#A', 'digest_algorithm' => 'md5']]], 'The "digest_algorithm" of references[0]'],
            'a reference with transforms that are not a list' => [['references' => [['uri' => '#A', 'transforms' => 'c14n']]], 'The "transforms" of references[0] must be a list'],
            'a reference with transforms that are not a list of items' => [['references' => [['uri' => '#A', 'transforms' => ['a' => 'c14n']]]], 'The "transforms" of references[0] must be a list'],
            'a transform that does not exist' => [['references' => [['uri' => '#A', 'transforms' => ['base64']]]], 'is not supported: use enveloped, c14n, exc_c14n or an xpath'],
            'a canonicalization with comments' => [['references' => [['uri' => '#A', 'transforms' => ['c14n_with_comments']]]], 'is not supported'],
            'a transform that is not a name nor an array' => [['references' => [['uri' => '#A', 'transforms' => [1]]]], 'The value of a transform of references[0] must be an array'],
            'a transform with a key that does not exist' => [['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath', 'expression' => '/a', 'x' => 1]]]]], 'The key "x" of a transform of references[0]'],
            'a transform of another type' => [['references' => [['uri' => '#A', 'transforms' => [['type' => 'base64']]]]], 'must have the "type" xpath and its "expression"'],
            'an xpath without expression' => [['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath']]]]], 'must have the "type" xpath and its "expression"'],
            'an xpath with an empty expression' => [['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath', 'expression' => '']]]]], 'must have the "type" xpath and its "expression"'],
            'an xpath with namespaces that are not valid' => [['references' => [['uri' => '#A', 'transforms' => [['type' => 'xpath', 'expression' => '/a', 'namespaces' => ['a b' => 'urn:a']]]]]], 'map of prefixes'],

            'objects that are not a list' => [['objects' => ['a' => ['xml' => '<a/>']]], '"objects" must be a list'],
            'an object that is not an array' => [['objects' => ['<a/>']], 'The value of objects[0] must be an array'],
            'an object with a key that does not exist' => [['objects' => [['xml' => '<a/>', 'name' => 'a']]], 'The key "name" of objects[0] is not valid'],
            'an object without xml' => [['objects' => [['id' => 'a']]], 'The "xml" of objects[0] is the content of the object'],
            'an object with xml that is empty' => [['objects' => [['xml' => ' ']]], 'The "xml" of objects[0] is the content of the object'],
            'an object with xml that is not well formed' => [['objects' => [['xml' => '<a>']]], 'is not well formed XML'],
            'an object with a prefix that is not declared' => [['objects' => [['xml' => '<p:a/>']]], 'is not well formed XML'],
            'an object with an id that is not a string' => [['objects' => [['xml' => '<a/>', 'id' => 1]]], 'The "id" of objects[0] must be a string'],
            'an object with a mime type that is not a string' => [['objects' => [['xml' => '<a/>', 'mime_type' => 1]]], 'The "mime_type" of objects[0] must be a string'],
            'an object with an encoding that is not a string' => [['objects' => [['xml' => '<a/>', 'encoding' => 1]]], 'The "encoding" of objects[0] must be a string'],
            'a resource without resolver' => [['references' => [['uri' => 'data.txt']]], 'needs the option "resource_resolver"'],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('invalidOptionsProvider')]
    public function testAnOptionThatIsNotValidIsAnErrorOfTheSignature(array $options, string $detail): void
    {
        try {
            $this->service->signXml('<Root><Doc ID="A"/></Root>', $this->certificate, $options);
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertStringStartsWith('The options of the signature are not valid: ', $e->getMessage());
            $this->assertStringContainsString($detail, $e->getMessage());
        }
    }

    public function testTheOptionsAreAlsoValidatedWhenTheyAreAnOptionsObject(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('digest_algorithm');

        $this->service->signXml('<Root/>', $this->certificate, new Options(['digest_algorithm' => 'md5']));
    }

    public function testTheOptionsThatAreNotGivenInAnOptionsObjectAreTheDefaults(): void
    {
        $signed = $this->service->signXml('<Root><Doc ID="A"/></Root>', $this->certificate, new Options(['reference' => 'A']));

        $this->assertSame(
            $this->service->signXml('<Root><Doc ID="A"/></Root>', $this->certificate, ['reference' => 'A']),
            $signed
        );
    }

    public function testASignatureWithoutKeyInfoThatIsConfiguredWithAnotherKindOfKeyKeepsWorking(): void
    {
        $certificate = $this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        $signature = (new Signature())
            ->setData(['Signature' => ['SignedInfo' => []]])
            ->configureSignatureData('digest', $certificate)
        ;

        $this->assertNotNull($signature->getX509Certificate());
        $this->assertStringNotContainsString('KeyValue', (string) json_encode($signature->getData()));
    }
}
