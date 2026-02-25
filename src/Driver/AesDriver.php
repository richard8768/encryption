<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/encryption.
 *
 * @link     https://github.com/hyperf-ext/encryption
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/encryption/blob/master/LICENSE
 */

namespace HyperfExt\Encryption\Driver;

use HyperfExt\Encryption\Contract\SymmetricDriverInterface;
use HyperfExt\Encryption\Exception\DecryptException;
use HyperfExt\Encryption\Exception\EncryptException;
use RuntimeException;

class AesDriver implements SymmetricDriverInterface
{
    /**
     * The encryption key.
     *
     * @var string
     */
    protected string $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected string $cipher;

    /**
     * The supported cipher algorithms and their properties.
     *
     * @var array
     */
    private static array $supportedCiphers = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    /**
     * Create a new encrypter instance.
     *
     * @throws RuntimeException
     */
    public function __construct(array $options = [])
    {
        $key = base64_decode((string)($options['key'] ?? ''));
        $cipher = (string)($options['cipher'] ?? 'aes-128-cbc');

        if (static::supported($key, $cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported ciphers are aes-128-cbc and AES-256-CBC with the correct key lengths.');
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     */
    public static function supported(string $key, string $cipher): bool
    {
        if (!isset(self::$supportedCiphers[strtolower($cipher)])) {
            return false;
        }

        return mb_strlen($key, '8bit') === self::$supportedCiphers[strtolower($cipher)]['size'];
    }

    /**
     * Create a new encryption key for the given cipher.
     * @param array $options
     * @return string
     */
    public static function generateKey(array $options = []): string
    {
        $cipher = $options['cipher'] ?? 'aes-128-cbc';
        return random_bytes(self::$supportedCiphers[strtolower($cipher)]['size'] ?? 32);
    }

    /**
     * Encrypt the given value.
     *
     * @param $value
     * @param bool $serialize
     * @return string
     */
    public function encrypt($value, bool $serialize = true): string
    {
        $iv = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)));

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = \openssl_encrypt(
            $serialize ? serialize($value) : $value,
            strtolower($this->cipher), $this->key, 0, $iv, $tag
        );

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $iv = base64_encode($iv);
        $tag = base64_encode($tag ?? '');

        $mac = self::$supportedCiphers[strtolower($this->cipher)]['aead']
            ? '' // For AEAD-algorithms, the tag / MAC is returned by openssl_encrypt...
            : $this->hash($iv, $value, $this->key);

        $json = json_encode(compact('iv', 'value', 'mac', 'tag'), JSON_UNESCAPED_SLASHES);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * Decrypt the given value.
     *
     * @param string $payload
     * @param bool $unserialize
     *
     * @return mixed
     */
    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        $payload = $this->getJsonPayload($payload);

        $iv = base64_decode($payload['iv']);
        $tag = empty($payload['tag']) ? null : base64_decode($payload['tag']);
        $this->ensureTagIsValid($tag);

        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        $decrypted = \openssl_decrypt(
            $payload['value'],
            $this->cipher,
            $this->key,
            0,
            $iv,
            $tag ?? ''
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Get the encryption key.
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Create a MAC for the given value.
     *
     * @param string $iv
     * @param mixed $value
     * @return string
     */
    protected function hash(string $iv, mixed $value): string
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @throws DecryptException
     */
    protected function getJsonPayload(string $payload): array
    {
        $payload = json_decode(base64_decode($payload), true);

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!$this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        if (!$this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }

        return $payload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param mixed $payload
     * @return bool
     */
    protected function validPayload(mixed $payload): bool
    {
        if (!is_array($payload)||!isset($payload['iv'],$payload['value'],$payload['mac'])|| !is_string($payload['iv'])
            || !is_string($payload['value'])|| !is_string($payload['mac'])) {
            return false;
        }

        if (isset($payload['tag']) && !is_string($payload['tag'])) {
            return false;
        }

        return strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length(strtolower($this->cipher));
    }

    /**
     * Determine if the MAC for the given payload is valid.
     */
    protected function validMac(array $payload): bool
    {
        $bytes = random_bytes(16);
        $calculated = $this->calculateMac($payload, $bytes);

        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true),
            $calculated
        );
    }

    /**
     * Calculate the hash of the given payload.
     *
     * @param array $payload
     * @param string $bytes
     * @return string
     */
    protected function calculateMac(array $payload, string $bytes): string
    {
        return hash_hmac(
            'sha256',
            $this->hash($payload['iv'], $payload['value']),
            $bytes,
            true
        );
    }

    /**
     * Ensure the given tag is a valid tag given the selected cipher.
     *
     * @param string $tag
     * @return void
     */
    protected function ensureTagIsValid(string $tag): void
    {
        if (self::$supportedCiphers[strtolower($this->cipher)]['aead'] && strlen($tag) !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (!self::$supportedCiphers[strtolower($this->cipher)]['aead'] && is_string($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }
    }
}
