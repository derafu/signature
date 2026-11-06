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

/**
 * Algorithms of XML Signature that the package signs and validates, by the name
 * that the options use and by their URI.
 *
 * It is the only place where the URIs are: the generator and the validator
 * read the same tables.
 */
final class Algorithms
{
    public const string ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    public const string XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';

    public const string C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    public const string C14N_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    public const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public const string EXC_C14N_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    /**
     * Transforms (besides the XPath and the enveloped signature ones) that
     * canonicalize, by name: the URI, if it is the exclusive algorithm and if it
     * keeps the comments.
     *
     * @var array<string, array{uri: string, exclusive: bool, comments: bool}>
     */
    public const array CANONICALIZATIONS = [
        'c14n' => ['uri' => self::C14N, 'exclusive' => false, 'comments' => false],
        'c14n_with_comments' => ['uri' => self::C14N_WITH_COMMENTS, 'exclusive' => false, 'comments' => true],
        'exc_c14n' => ['uri' => self::EXC_C14N, 'exclusive' => true, 'comments' => false],
        'exc_c14n_with_comments' => ['uri' => self::EXC_C14N_WITH_COMMENTS, 'exclusive' => true, 'comments' => true],
    ];

    /**
     * Digest algorithms of the references, by name: the URI and the name of the
     * hash.
     *
     * @var array<string, array{uri: string, hash: string}>
     */
    public const array DIGESTS = [
        'sha1' => ['uri' => 'http://www.w3.org/2000/09/xmldsig#sha1', 'hash' => 'sha1'],
        'sha224' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#sha224', 'hash' => 'sha224'],
        'sha256' => ['uri' => 'http://www.w3.org/2001/04/xmlenc#sha256', 'hash' => 'sha256'],
        'sha384' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#sha384', 'hash' => 'sha384'],
        'sha512' => ['uri' => 'http://www.w3.org/2001/04/xmlenc#sha512', 'hash' => 'sha512'],
    ];

    /**
     * Algorithms of the signature of the `SignedInfo`, by name: the URI, the
     * type of key that signs (`OPENSSL_KEYTYPE_*`) and the algorithm of OpenSSL.
     *
     * @var array<string, array{uri: string, key: int, openssl: int}>
     */
    public const array SIGNATURES = [
        'rsa-sha1' => ['uri' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'key' => OPENSSL_KEYTYPE_RSA, 'openssl' => OPENSSL_ALGO_SHA1],
        'rsa-sha224' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224', 'key' => OPENSSL_KEYTYPE_RSA, 'openssl' => OPENSSL_ALGO_SHA224],
        'rsa-sha256' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 'key' => OPENSSL_KEYTYPE_RSA, 'openssl' => OPENSSL_ALGO_SHA256],
        'rsa-sha384' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', 'key' => OPENSSL_KEYTYPE_RSA, 'openssl' => OPENSSL_ALGO_SHA384],
        'rsa-sha512' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', 'key' => OPENSSL_KEYTYPE_RSA, 'openssl' => OPENSSL_ALGO_SHA512],
        'ecdsa-sha1' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1', 'key' => OPENSSL_KEYTYPE_EC, 'openssl' => OPENSSL_ALGO_SHA1],
        'ecdsa-sha224' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224', 'key' => OPENSSL_KEYTYPE_EC, 'openssl' => OPENSSL_ALGO_SHA224],
        'ecdsa-sha256' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256', 'key' => OPENSSL_KEYTYPE_EC, 'openssl' => OPENSSL_ALGO_SHA256],
        'ecdsa-sha384' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384', 'key' => OPENSSL_KEYTYPE_EC, 'openssl' => OPENSSL_ALGO_SHA384],
        'ecdsa-sha512' => ['uri' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512', 'key' => OPENSSL_KEYTYPE_EC, 'openssl' => OPENSSL_ALGO_SHA512],
        'dsa-sha1' => ['uri' => 'http://www.w3.org/2000/09/xmldsig#dsa-sha1', 'key' => OPENSSL_KEYTYPE_DSA, 'openssl' => OPENSSL_ALGO_SHA1],
        'dsa-sha256' => ['uri' => 'http://www.w3.org/2009/xmldsig11#dsa-sha256', 'key' => OPENSSL_KEYTYPE_DSA, 'openssl' => OPENSSL_ALGO_SHA256],
    ];

    /**
     * Gives the name of the hash of a digest algorithm.
     *
     * @param string $uri URI of the `DigestMethod`.
     * @return string|null Name of the hash, or `null` if it is not supported.
     */
    public static function hashByUri(string $uri): ?string
    {
        foreach (self::DIGESTS as $digest) {
            if ($digest['uri'] === $uri) {
                return $digest['hash'];
            }
        }

        return null;
    }

    /**
     * Gives the algorithm of a signature.
     *
     * @param string $uri URI of the `SignatureMethod`.
     * @return array{uri: string, key: int, openssl: int}|null The algorithm, or
     * `null` if it is not supported.
     */
    public static function signatureByUri(string $uri): ?array
    {
        foreach (self::SIGNATURES as $signature) {
            if ($signature['uri'] === $uri) {
                return $signature;
            }
        }

        return null;
    }
}
