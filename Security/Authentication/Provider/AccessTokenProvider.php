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
     *
     * @return ApiToken
     */
    public function fromUser($user)
    {
        //first check if an accessToken already exists for the user
        //first check if a hash has been already created, then check if it's valid
        $redisKey = 'nazka_user:' . $user->getId();
        $hash = $this->redis->get($redisKey);

        if (!$hash || !$this->searchHash($hash)) {
            //if doesn't exist, create a new hash and store user basic data (classname, id).

            $hash = $this->storeAccessToken($user, array('ROLE_USER'));
            // store hash in nazka_user_{id}:hash, so we can find if it exists on user login.
            $this->redis->setex($redisKey, 3600, $hash);
        }

        return $hash;
    }

    /**
     * @param  stribgn     $hash
     * @return object|null
     */
    protected function searchHash($hash)
    {
        list($user, $roles) = $this->persitenceProvider->find($hash);
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
    protected function storeAccessToken(UserInterface $entity, $roles)
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
