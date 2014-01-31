<?php

namespace Nazka\AccessTokenSecurityBundle\Security\Authentication\Token;

use InvalidArgumentException;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class ApiToken extends AbstractToken
{
    public $accessToken;

    public function __construct($user, $providerKey, array $roles = array(), $fbToken = null)
    {
        parent::__construct($roles);

        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->setUser($user);
        $this->providerKey = $providerKey;
        $this->fbToken = $fbToken;

        // If the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);
    }

    public function getCredentials()
    {
        return '';
    }
}
