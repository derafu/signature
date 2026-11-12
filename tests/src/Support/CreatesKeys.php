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
use Derafu\Certificate\Service\CertificateLoader;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

/**
 * Creates certificates with keys that are not RSA, to sign with them, and gives
 * them to `xmlsec1`. It is used with `UsesXmlsec`.
 */
trait CreatesKeys
{
    /**
     * Creates a self-signed certificate with a new key.
     *
     * @param array<string, mixed> $key Configuration of the key, as
     * `openssl_pkey_new()` takes it.
     */
    private function createCertificate(array $key): CertificateInterface
    {
        $pair = openssl_pkey_new($key);
        if (!$pair instanceof OpenSSLAsymmetricKey) {
            $this->fail('OpenSSL could not make the key.');
        }
        // OpenSSL takes the key by reference here, a copy keeps the type of it.
        $copy = $pair;
        $request = openssl_csr_new(['commonName' => 'derafu test'], $copy);
        if (!$request instanceof OpenSSLCertificateSigningRequest) {
            $this->fail('OpenSSL could not make the request of the certificate.');
        }
        $certificate = openssl_csr_sign($request, null, $pair, 2);
        if (!$certificate instanceof OpenSSLCertificate) {
            $this->fail('OpenSSL could not sign the certificate.');
        }

        $certificatePem = '';
        $privateKeyPem = '';
        $this->assertTrue(openssl_x509_export($certificate, $certificatePem));
        $copy = $pair;
        $this->assertTrue(openssl_pkey_export($copy, $privateKeyPem));
        $this->assertIsString($certificatePem);
        $this->assertIsString($privateKeyPem);

        return (new CertificateLoader())->loadFromKeys($certificatePem, $privateKeyPem);
    }

    /**
     * Creates a certificate with a DSA key of 1024 bits and an order of 160
     * bits, the one that `dsa-sha1` is defined for. OpenSSL makes the keys with
     * a larger order if it is not asked for it.
     *
     * @return CertificateInterface|null `null` if OpenSSL can not make it.
     */
    private function createDsaCertificateWithOrder160(): ?CertificateInterface
    {
        $directory = sys_get_temp_dir() . '/derafu-signature-dsa-' . bin2hex(random_bytes(6));
        mkdir($directory);
        $parameters = escapeshellarg($directory . '/parameters.pem');
        $key = escapeshellarg($directory . '/key.pem');
        $certificate = escapeshellarg($directory . '/cert.pem');

        $commands = [
            'openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -pkeyopt dsa_paramgen_q_bits:160 -out ' . $parameters,
            'openssl genpkey -paramfile ' . $parameters . ' -out ' . $key,
            'openssl req -new -x509 -key ' . $key . ' -subj /CN=derafu -days 2 -out ' . $certificate,
        ];
        $made = true;
        foreach ($commands as $command) {
            exec($command . ' 2>&1', $lines, $status);
            if ($status !== 0) {
                $made = false;
                break;
            }
        }

        $result = $made
            ? (new CertificateLoader())->loadFromKeys(
                (string) file_get_contents($directory . '/cert.pem'),
                (string) file_get_contents($directory . '/key.pem')
            )
            : null;

        foreach (glob($directory . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($directory);

        return $result;
    }
}
