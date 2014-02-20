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

    private $persitenceProvider;
    private $providerKey;
    private $fbToken = null;

    /**
     * 
     * @param \Nazka\AccessTokenSecurityBundle\Persistence\PersistenceInterface $persitenceProvider
     * @param type $providerKey
     */
    public function __construct(PersistenceInterface $persitenceProvider, $providerKey)
    {
        $this->persitenceProvider = $persitenceProvider;
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
            $hash = $this->persitenceProvider->findHashByUser($user);



        return $hash;
    }

    /**
     * @param  string     $hash
     * @return ApiToken|null
     */
    protected function searchHash($hash)
    {
        list($user, $roles) = $this->persitenceProvider->findUserByHash($hash);
        if ($user) {
            $apiToken = $this->createApiToken($user, $roles);

            return $apiToken;
        }

        return null;
    }

    /**
     * From a Token create a hash as client's accessToken and store it
     *
     * @param  TokenInterface $token
     * @return string
     */
    protected function createAccessToken(UserInterface $entity, array $roles)
    {
        $tokenGenerator = new TokenGenerator();
        $hashToken = $tokenGenerator->generateToken();

        //Persist hash
        $this->persitenceProvider->storeHash($hashToken, $entity, $roles);

        return $hashToken;
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
