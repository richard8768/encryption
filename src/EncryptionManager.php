<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/encryption.
 *
 * @link     https://github.com/hyperf-ext/encryption
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/encryption/blob/master/LICENSE
 */

namespace HyperfExt\Encryption;

use Hyperf\Contract\ConfigInterface;
use HyperfExt\Encryption\Contract\DriverInterface;
use HyperfExt\Encryption\Contract\EncryptionInterface;
use HyperfExt\Encryption\Driver\AesDriver;
use InvalidArgumentException;

class EncryptionManager implements EncryptionInterface
{
    /**
     * The config instance.
     *
     * @var ConfigInterface
     */
    protected $config;

    /**
     * The array of created "drivers".
     *
     * @var DriverInterface[]
     */
    protected $drivers = [];

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
    }

    public function encrypt($value, bool $serialize = true): string
    {
        return $this->getDriver()->encrypt($value, $serialize);
    }

    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        return $this->getDriver()->decrypt($payload, $unserialize);
    }

    /**
     * Get a driver instance.
     *
     * @param string|null $name
     * @return DriverInterface
     */
    public function getDriver(?string $name = null): DriverInterface
    {
        if (isset($this->drivers[$name]) && $this->drivers[$name] instanceof DriverInterface) {
            return $this->drivers[$name];
        }

        $name = $name ?: $this->config->get('encryption.default', 'aes');

        $config = $this->config->get("encryption.driver.{$name}");
        if (empty($config) or empty($config['class'])) {
            throw new InvalidArgumentException(sprintf('The encryption driver config %s is invalid.', $name));
        }

        $driverClass = $config['class'] ?? AesDriver::class;

        $driver = \Hyperf\Support\make($driverClass, ['options' => $config['options'] ?? []]);

        return $this->drivers[$name] = $driver;
    }
}
