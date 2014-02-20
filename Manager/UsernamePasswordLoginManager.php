<?php

namespace Nazka\AccessTokenSecurityBundle\Manager;

use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * Check a username password login in a given firewall with a UsernamePasswordToken
 *
 * @author javier
 */
class UsernamePasswordLoginManager
{

    private $authenticationManager;
    private $firewall;

    public function __construct(AuthenticationManagerInterface $authenticationManager, $firewall)
    {
        $this->authenticationManager = $authenticationManager;
        $this->firewall = $firewall;
    }

    public function checkLogin($username, $password)
    {
        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->firewall));
    }
}
