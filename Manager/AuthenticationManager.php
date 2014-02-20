<?php

namespace Nazka\AccessTokenSecurityBundle\Manager;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Nazka\AccessTokenSecurityBundle\Security\Authentication\Token\ApiToken;
use Nazka\AccessTokenSecurityBundle\Security\Authentication\Provider\AccessTokenProvider;


/**
 * Token hash generation and mapping a User entity to Redis
 * @author Javier Sampedro <jsampedro77@gmail.com>
 */
class AuthenticationManager implements AuthenticationProviderInterface
{
    private $accessTokenProvider;

    public function __construct(AccessTokenProvider $accessTokenProvider)
    {
        $this->accessTokenProvider = $accessTokenProvider;
    }

    /**
     * Get an AccessToken from another valid TokenInterface
     *
     * @param  UserInterface $user
     * @return string
     */
    public function getAccessTokenFrom(TokenInterface $token)
    {
        $hash = $this->accessTokenProvider->fromUser($token->getUser());

        if (!$hash) {
            //if doesn't exist, create a new hash with user and roles
            $hash = $this->accessTokenProvider->createAccessToken($token->getUser(), $token->getRoles());
        }
        
        return $hash;
    }

    /**
     * Try to get a valid ApiToken from ApiToken.accessToken
     *
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     */
    public function authenticate(TokenInterface $token)
    {
        return $this->accessTokenProvider->fromHash($token->accessToken);
    }

    public function supports(TokenInterface $token = null)
    {
        return $token instanceof ApiToken;
    }

    /**
     * Checks user is enabled
     *
     * @param  User                      $user
     * @throws AccessDeniedHttpException
     */
    protected function checkUserAccess(UserInterface $user)
    {
        if (!$user->isEnabled() || $user->isLocked()) {
            throw new AccessDeniedHttpException('User locked or access disabled');
        }
    }
}
