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

use Derafu\Signature\Contract\ResourceResolverInterface;
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
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The signatures that are not in a document (detached): what they sign is a
 * resource that a resolver gives, or an `Object` of the signature. The ones that
 * the library makes `xmlsec1` verifies, and the ones that `xmlsec1` makes the
 * library validates.
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
final class SignatureDetachedTest extends TestCase
{
    use UsesXmlsec;

    private const UBL = '<Invoice xmlns="urn:invoice" xmlns:sig="urn:sig"><cbc:ID xmlns:cbc="urn:cbc">INV-1</cbc:ID>'
        . '<sig:UBLDocumentSignatures><x/></sig:UBLDocumentSignatures></Invoice>';

    private const UBL_EXPRESSION = 'count(ancestor-or-self::sig:UBLDocumentSignatures)=0';

    protected function setUp(): void
    {
        $this->createService();
    }

    /**
     * Gives a resolver of resources by their `URI`.
     *
     * @param array<string, string> $resources
     */
    private function resolver(array $resources): ResourceResolverInterface
    {
        return new class ($resources) implements ResourceResolverInterface {
            /**
             * @param array<string, string> $resources
             */
            public function __construct(private readonly array $resources)
            {
            }

            public function resolve(string $uri): string
            {
                return $this->resources[$uri] ?? throw new RuntimeException('The resource ' . $uri . ' does not exist.');
            }
        };
    }

    public function testASignatureOfAResourceIsADocumentOfItsOwnAndIsValidatedWithTheResource(): void
    {
        $resolver = $this->resolver(['data.txt' => "hello\nworld"]);

        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => 'data.txt']],
            'resource_resolver' => $resolver,
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
            'signature_prefix' => 'ds',
        ]);

        $this->assertStringStartsWith('<?xml version="1.0"?>' . "\n" . '<ds:Signature xmlns:ds="' . self::DSIG . '">', $signed);
        $this->assertStringContainsString('<ds:Reference URI="data.txt">', $signed);
        $this->assertStringNotContainsString('Transforms', $signed);
        $results = $this->service->validateXml($signed, ['resource_resolver' => $resolver]);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAChangeOfTheResourceMakesTheSignatureNotValid(): void
    {
        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => 'data.txt']],
            'resource_resolver' => $this->resolver(['data.txt' => 'hello']),
        ]);

        $results = $this->service->validateXml($signed, ['resource_resolver' => $this->resolver(['data.txt' => 'hello!'])]);

        $this->assertFalse($results[0]->isValid());
    }

    public function testWithoutTheResolverTheSignatureOfAResourceIsNotValid(): void
    {
        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => 'data.txt']],
            'resource_resolver' => $this->resolver(['data.txt' => 'hello']),
        ]);

        $results = $this->service->validateXml($signed);

        $this->assertFalse($results[0]->isValid());
        $this->assertStringContainsString(
            'points to a resource that is not in the document, and no resource resolver was given',
            (string) $results[0]->getError()?->getMessage()
        );
    }

    public function testAnXmlResourceIsCanonicalizedAndItsFormatDoesNotMatter(): void
    {
        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => 'invoice.xml', 'transforms' => ['c14n']]],
            'resource_resolver' => $this->resolver(['invoice.xml' => "<a b='1'><c/></a>"]),
        ]);

        $results = $this->service->validateXml($signed, [
            'resource_resolver' => $this->resolver(['invoice.xml' => '<a   b="1"><c></c></a>']),
        ]);

        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testTheXPathOfTheDetachedProfileSelectsTheNodesOfTheResource(): void
    {
        $options = [
            'references' => [[
                'uri' => 'invoice.xml',
                'transforms' => [
                    ['type' => 'xpath', 'expression' => self::UBL_EXPRESSION, 'namespaces' => ['sig' => 'urn:sig']],
                    'c14n',
                ],
            ]],
            'digest_algorithm' => 'sha256',
            'signature_prefix' => 'ds',
        ];

        $signed = $this->service->signXmlDetached($this->certificate, $options + [
            'resource_resolver' => $this->resolver(['invoice.xml' => self::UBL]),
        ]);

        // What the profile leaves out of the data can change.
        $withSignatures = str_replace('<x/>', '<x>other signature</x>', self::UBL);
        $results = $this->service->validateXml($signed, ['resource_resolver' => $this->resolver(['invoice.xml' => $withSignatures])]);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());

        // What it does not, can not.
        $changed = str_replace('INV-1', 'INV-2', self::UBL);
        $results = $this->service->validateXml($signed, ['resource_resolver' => $this->resolver(['invoice.xml' => $changed])]);
        $this->assertFalse($results[0]->isValid());
    }

    public function testTheXPathOfAResourceThatIsNotInTheDocumentCanNotUseHere(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('can not use here()');

        $this->service->signXmlDetached($this->certificate, [
            'references' => [[
                'uri' => 'invoice.xml',
                'transforms' => [['type' => 'xpath', 'expression' => 'here()/ancestor::*']],
            ]],
            'resource_resolver' => $this->resolver(['invoice.xml' => self::UBL]),
        ]);
    }

    public function testTheResourceAndAnObjectOfTheSignatureAreSignedTogether(): void
    {
        $resolver = $this->resolver(['data.txt' => 'hello']);
        $options = [
            'references' => [['uri' => 'data.txt'], ['uri' => '#props-1']],
            'objects' => [['xml' => '<p:Properties xmlns:p="urn:p" Id="props-1">v</p:Properties>']],
            'resource_resolver' => $resolver,
            'signature_id' => 'signature-1',
        ];

        $signed = $this->service->signXmlDetached($this->certificate, $options);

        $results = $this->service->validateXml($signed, ['resource_resolver' => $resolver]);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertFalse($this->service->validateXml(str_replace('>v<', '>w<', $signed), ['resource_resolver' => $resolver])[0]->isValid());
    }

    public function testASignatureOfAnObjectDoesNotNeedAResolver(): void
    {
        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => '#props-1']],
            'objects' => [['xml' => '<p:Properties xmlns:p="urn:p" Id="props-1">v</p:Properties>']],
        ]);

        $results = $this->service->validateXml($signed);

        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAReferenceWithoutTheHashIsAnElementOfTheDocumentWhenItExists(): void
    {
        // Some systems write the `URI` of an element without the `#`.
        $signed = $this->service->signXml('<Root><Doc ID="A"/></Root>', $this->certificate, ['reference' => 'A']);
        $withoutHash = str_replace('URI="#A"', 'URI="A"', $signed);

        $results = $this->service->validateXml($withoutHash);

        $this->assertCount(1, $results);
        $this->assertFalse($results[0]->isValid());
        $this->assertStringContainsString('The electronic signature', (string) $results[0]->getError()?->getMessage());
    }

    public function testTheResolverIsOnlyAskedForTheResourcesThatAreNotInTheDocument(): void
    {
        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => '#props-1']],
            'objects' => [['xml' => '<p:Properties xmlns:p="urn:p" Id="props-1">v</p:Properties>']],
        ]);

        $results = $this->service->validateXml($signed, ['resource_resolver' => $this->resolver([])]);

        $this->assertTrue($results[0]->isValid());
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidDetachedOptionsProvider(): array
    {
        $resolver = new class () implements ResourceResolverInterface {
            public function resolve(string $uri): string
            {
                return '';
            }
        };

        return [
            'without references' => [[], 'a detached signature needs the option "references"'],
            'with reference' => [['reference' => 'A'], 'a detached signature needs the option "references"'],
            'with a location' => [
                ['references' => [['uri' => '#a']], 'signature_location' => ['xpath' => '/a']],
                'a detached signature is not placed in a document',
            ],
            'a resource without resolver' => [
                ['references' => [['uri' => 'data.txt']]],
                'the reference "data.txt" is not in the document, so it needs the option "resource_resolver"',
            ],
            'a resolver that is not one' => [
                ['references' => [['uri' => 'data.txt']], 'resource_resolver' => 'file'],
                'resource_resolver',
            ],
            'a resolver of the wrong kind' => [
                ['references' => [['uri' => 'data.txt']], 'resource_resolver' => $resolver, 'digest_algorithm' => 'md5'],
                'digest_algorithm',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('invalidDetachedOptionsProvider')]
    public function testTheOptionsOfADetachedSignatureThatAreNotValidAreAnError(array $options, string $detail): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('The options of the signature are not valid');
        $this->expectExceptionMessage($detail);

        $this->service->signXmlDetached($this->certificate, $options);
    }

    public function testAResourceThatIsNotInTheDocumentNeedsTheResolverToSignTheDocumentToo(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('the reference "data.txt" is not in the document, so it needs the option "resource_resolver"');

        $this->service->signXml('<Root/>', $this->certificate, ['references' => [['uri' => 'data.txt']]]);
    }

    public function testADocumentSignedWithAReferenceToAResourceAndOneToItsElement(): void
    {
        $resolver = $this->resolver(['data.txt' => 'hello']);

        $signed = $this->service->signXml('<Root><Doc ID="A"><V>1</V></Doc></Root>', $this->certificate, [
            'references' => [['uri' => '#A'], ['uri' => 'data.txt']],
            'resource_resolver' => $resolver,
        ]);

        $results = $this->service->validateXml($signed, ['resource_resolver' => $resolver]);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertFalse($this->service->validateXml($signed)[0]->isValid());
    }

    public function testTheOptionsOfTheValidationThatAreNotValidAreAnError(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('The options of the signature are not valid');

        $this->service->validateXml('<Root/>', ['resource_resolver' => 'file']);
    }

    public function testADetachedSignatureThatXmlsecVerifiesWithTheResourceInAFile(): void
    {
        $this->requireXmlsec();
        $file = $this->xmlsecDirectory . '/data.txt';
        file_put_contents($file, "hello\nworld");
        $uri = 'file://' . $file;

        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => $uri]],
            'resource_resolver' => $this->resolver([$uri => "hello\nworld"]),
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
            'signature_prefix' => 'ds',
        ]);

        $this->assertTrue($this->verifyDetachedWithXmlsec($signed));
        file_put_contents($file, 'changed');
        $this->assertFalse($this->verifyDetachedWithXmlsec($signed));
    }

    public function testADetachedSignatureThatXmlsecMakesIsValidatedByTheLibrary(): void
    {
        $this->requireXmlsec();
        $file = $this->xmlsecDirectory . '/data.txt';
        file_put_contents($file, "hello\nworld");
        $uri = 'file://' . $file;
        $template = $this->template('ds', self::SIGNATURES['sha256'], self::C14N, [[$uri, self::DIGESTS['sha256'], []]]);
        $template = '<?xml version="1.0"?>' . "\n" . str_replace('<ds:Signature ', '<ds:Signature ', $template);

        $input = $this->xmlsecDirectory . '/template.xml';
        $output = $this->xmlsecDirectory . '/detached.xml';
        file_put_contents($input, $template);
        exec(
            'xmlsec1 --sign --enabled-reference-uris empty,same-doc,local --privkey-pem:key '
            . escapeshellarg($this->xmlsecDirectory . '/key.pem') . ',' . escapeshellarg($this->xmlsecDirectory . '/cert.pem')
            . ' --output ' . escapeshellarg($output) . ' ' . escapeshellarg($input) . ' 2>&1',
            $lines,
            $status
        );
        $this->assertSame(0, $status, implode("\n", $lines));

        $signed = (string) file_get_contents($output);
        $results = $this->service->validateXml($signed, ['resource_resolver' => $this->resolver([$uri => "hello\nworld"])]);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    /**
     * Verifies a detached signature with `xmlsec1`, that reads the resources
     * that are in files.
     */
    private function verifyDetachedWithXmlsec(string $signed): bool
    {
        $file = $this->xmlsecDirectory . '/detached.xml';
        file_put_contents($file, $signed);
        exec(
            'xmlsec1 --verify --insecure --enabled-reference-uris empty,same-doc,local '
            . escapeshellarg($file) . ' 2>&1',
            $lines,
            $status
        );

        return $status === 0 && str_contains(implode("\n", $lines), 'Verification status: OK');
    }
}
