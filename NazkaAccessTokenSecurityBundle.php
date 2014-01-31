<?php

namespace Nazka\AccessTokenSecurityBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Nazka\AccessTokenSecurityBundle\DependencyInjection\Security\Factory\ApiFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class NazkaAccessTokenSecurityBundle extends Bundle
{

    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new ApiFactory());
    }

}
