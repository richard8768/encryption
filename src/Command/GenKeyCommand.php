<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/encryption.
 *
 * @link     https://github.com/hyperf-ext/encryption
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/encryption/blob/master/LICENSE
 */
namespace HyperfExt\Encryption\Command;

use Hyperf\Command\Command as HyperfCommand;
use Hyperf\Contract\ConfigInterface;

class GenKeyCommand extends HyperfCommand
{
    /**
     * The repository instance.
     *
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
        parent::__construct('gen:key');
    }

    public function configure(): void
    {
        parent::configure();
        $this->setDescription('Create a secret key or key-pair for hyperf-ext/encryption');
    }

    /**
     * Handle the current command.
     */
    public function handle(): void
    {
        $driverName = $this->choice('Select driver', array_keys($this->config->get('encryption.driver')));

        $key = $this->generateRandomKey($driverName);

        $this->line('key:<comment>' . $key . '</comment>');
        $this->line('base64_encode:<comment>' . base64_encode($key) . '</comment>');
    }

    /**
     * Generate a random key for the application.
     *
     * @param string $driverName
     * @return string
     */
    protected function generateRandomKey(string $driverName): string
    {
        $config = $this->config->get("encryption.driver.{$driverName}");
        return call([$config['class'], 'generateKey'], [$config['options']]);
    }
}
