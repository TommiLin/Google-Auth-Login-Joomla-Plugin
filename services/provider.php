<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.googleauth
 *
 * @copyright   Copyright (C) 2026 TommiLin. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
defined('_JEXEC') or die;

use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Database\DatabaseInterface;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Event\DispatcherInterface;
use Joomla\Plugin\System\Googleauth\Extension\Googleauth;

return new class implements ServiceProviderInterface
{
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                $instance = new Googleauth(
                    $container->get(DispatcherInterface::class),
                    (array) PluginHelper::getPlugin('system', 'googleauth')
                );

                $instance->setApplication(Factory::getApplication());
                $instance->setDatabase($container->get(DatabaseInterface::class));

                return $instance;
            }
        );
    }
};
