<?php

namespace Nazka\AccessTokenSecurityBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use \Symfony\Component\Security\Core\User\UserInterface;
use Nazka\AccessTokenSecurityBundle\Security\Authentication\Token\ApiToken;
use Nazka\AccessTokenSecurityBundle\Util\TokenGenerator;
use Nazka\AccessTokenSecurityBundle\Persistence\PersistenceInterface;

/**
 * @author Javier Sampedro <jsampedro77@gmail.com>
 */
class AccessTokenProvider
{

    private $persistenceProvider;
    private $providerKey;
    private $fbToken = null;

    /**
     * 
     * @param \Nazka\AccessTokenSecurityBundle\Persistence\PersistenceInterface $persistenceProvider
     * @param type $providerKey
     */
    public function __construct(PersistenceInterface $persistenceProvider, $providerKey)
    {
        $this->persistenceProvider = $persistenceProvider;
        $this->providerKey = $providerKey;
    }

    /**
     * @param  string   $hash
     * @return ApiToken
     */
    public function fromHash($hash)
    {
        // try to recover api token from persitence provider
        $token = $this->searchHash($hash);

        return $token;
    }

    /**
     * Returns a valid accessToken key
     *
     * @return ApiToken
     */
    public function fromUser(UserInterface $user)
    {
        //first check if an accessToken already exists for the user
        $hash = $this->persistenceProvider->findHashByUser($user);

        return $hash;
    }

    /**
     * From a Token create a hash as client's accessToken and store it
     *
     * @param  TokenInterface $token
     * @return string
     */
    public function createAccessToken(UserInterface $entity, array $roles)
    {
        $tokenGenerator = new TokenGenerator();
        $hashToken = $tokenGenerator->generateToken();

        //Persist hash
        $this->persistenceProvider->storeHash($hashToken, $entity, $roles);

        return $hashToken;
    }

    /**
     * @param  string     $hash
     * @return ApiToken|null
     */
    protected function searchHash($hash)
    {
        list($user, $roles) = $this->persistenceProvider->findUserByHash($hash);
        if ($user) {
            $apiToken = $this->createApiToken($user, $roles);

            return $apiToken;
        }

        return null;
    }

    /**
     * @param  object   $user
     * @param  array    $roles
     * @return ApiToken
     */
    protected function createApiToken(UserInterface $user, $roles = array())
    {
        return new ApiToken($user, $this->providerKey, $roles);
    }
}
