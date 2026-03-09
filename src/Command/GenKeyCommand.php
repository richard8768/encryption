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
use Hyperf\Di\Annotation\Inject;

class GenKeyCommand extends HyperfCommand
{
    /**
     * The repository instance.
     *
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    /**
     * The name and signature of the console command.
     */
    protected ?string $signature = 'gen:key
                            {--length=128 : The length of the key}';

    protected string $description = 'Create a secret key or key-pair for hyperf-ext/encryption';

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
        parent::__construct();
    }

    /**
     * Handle the current command.
     */
    public function handle(): void
    {
        $driverName = $this->choice('Select driver', array_keys($this->config->get('encryption.driver')));
        $length = $this->input->getOption('length') ?? '128';
        $key = $this->generateRandomKey($driverName, (int)$length);

        $this->line('key:<comment>' . $key . '</comment>');
        $this->line('base64_encode:<comment>' . base64_encode($key) . '</comment>');
    }

    /**
     * Generate a random key for the application.
     *
     * @param string $driverName
     * @param int $length
     * @return string
     */
    protected function generateRandomKey(string $driverName, int $length): string
    {
        $config = $this->config->get("encryption.driver.{$driverName}");
        $cipher = ($length == 128) ? 'aes-128-cbc' : 'aes-256-cbc';
        $config['options']['cipher'] = $cipher;
        return call([$config['class'], 'generateKey'], [$config['options']]);
    }
}
