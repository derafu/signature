<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature;

use Derafu\Certificate\Contract\CertificateFakerInterface;
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Contract\SignatureServiceInterface;
use Derafu\Signature\Contract\SignatureValidatorInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;

/**
 * Exercises the actual service configuration with real cryptographic operations.
 */
#[CoversNothing]
final class ServicesTest extends TestCase
{
    use ReadsFixtures;

    private function container(): ContainerBuilder
    {
        $root = dirname(__DIR__, 2);
        $container = new ContainerBuilder();
        $loader = new YamlFileLoader($container, new FileLocator($root . '/resources/config'));
        $loader->load($root . '/vendor/derafu/xml/resources/config/xml-services.yaml');
        $loader->load($root . '/vendor/derafu/certificate/resources/config/certificate-services.yaml');
        $loader->load('signature-services.yaml');
        $this->assertArrayHasKey(
            SignatureTranslationResourceProvider::class,
            $container->findTaggedServiceIds('derafu_translation.resource_provider')
        );
        $container->register('app.translator', Translator::class)
            ->setFactory([TranslatorFactory::class, 'create'])
            ->setArguments(['es', ['en'], new TaggedIteratorArgument('derafu_translation.resource_provider')]);
        foreach ($container->getDefinitions() as $definition) {
            $definition->setPublic(true);
        }
        $container->compile();

        return $container;
    }

    public function testConfigurationConstructsEveryDeclaredService(): void
    {
        $container = $this->container();
        $this->assertInstanceOf(SignatureService::class, $container->get(SignatureServiceInterface::class));
        $this->assertInstanceOf(SignatureGenerator::class, $container->get(SignatureGeneratorInterface::class));
        $this->assertInstanceOf(SignatureValidator::class, $container->get(SignatureValidatorInterface::class));
        $provider = $container->get(SignatureTranslationResourceProvider::class);
        $this->assertInstanceOf(SignatureTranslationResourceProvider::class, $provider);
        $directories = [...$provider->getDirectories()];
        $this->assertCount(1, $directories);
        $this->assertSame(realpath(dirname(__DIR__, 2) . '/resources/translations'), realpath($directories[0]));
    }

    public function testConfiguredGeneratorAndValidatorInteroperateWithTheService(): void
    {
        $container = $this->container();
        $faker = $container->get(CertificateFakerInterface::class);
        $this->assertInstanceOf(CertificateFakerInterface::class, $faker);
        $certificate = $faker->createFake();
        $generator = $container->get(SignatureGeneratorInterface::class);
        $this->assertInstanceOf(SignatureGeneratorInterface::class, $generator);
        $validator = $container->get(SignatureValidatorInterface::class);
        $this->assertInstanceOf(SignatureValidatorInterface::class, $validator);
        $service = $container->get(SignatureServiceInterface::class);
        $this->assertInstanceOf(SignatureServiceInterface::class, $service);

        $signature = $generator->sign('original data', $certificate->getPrivateKey());
        $this->assertTrue($service->validate('original data', $signature, $certificate->getCertificate()));
        $this->assertFalse($validator->validate('altered data', $signature, $certificate->getCertificate()));
        $serviceSignature = $service->sign('service data', $certificate->getPrivateKey());
        $this->assertTrue($validator->validate('service data', $serviceSignature, $certificate->getCertificate()));
    }

    public function testConfiguredServiceSignsAndValidatesXmlAndDetectsTampering(): void
    {
        $container = $this->container();
        $faker = $container->get(CertificateFakerInterface::class);
        $this->assertInstanceOf(CertificateFakerInterface::class, $faker);
        $service = $container->get(SignatureServiceInterface::class);
        $this->assertInstanceOf(SignatureServiceInterface::class, $service);
        $xml = $this->readFixture(dirname(__DIR__) . '/fixtures/unsigned_utf8.xml');

        $signed = $service->signXml($xml, $faker->createFake(), 'Derafu_SetDoc');
        $results = $service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid());
        $this->assertNull($results[0]->getError());

        $altered = str_replace('<Folio>1</Folio>', '<Folio>2</Folio>', $signed);
        $this->assertNotSame($signed, $altered);
        $invalidResults = $service->validateXml($altered);
        $this->assertCount(1, $invalidResults);
        $this->assertFalse($invalidResults[0]->isValid());
        $this->assertInstanceOf(SignatureException::class, $invalidResults[0]->getError());
    }

    public function testTaggedResourcesTranslateARealUnsignedXmlException(): void
    {
        $container = $this->container();
        $service = $container->get(SignatureServiceInterface::class);
        $this->assertInstanceOf(SignatureServiceInterface::class, $service);
        $translator = $container->get('app.translator');
        $this->assertInstanceOf(Translator::class, $translator);
        $xml = $this->readFixture(dirname(__DIR__) . '/fixtures/unsigned_utf8.xml');
        try {
            (void) $service->validateXml($xml);
            $this->fail('An unsigned XML document was accepted.');
        } catch (SignatureException $exception) {
            $this->assertSame('No se encontraron firmas para validar en el XML.', $exception->trans($translator));
        }
    }
}
