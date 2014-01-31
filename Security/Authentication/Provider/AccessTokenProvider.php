<?php

namespace Nazka\AccessTokenSecurityBundle\Security\Authentication\Provider;

use Nazka\AccessTokenSecurityBundle\Security\Authentication\Token\ApiToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Nazka\AccessTokenSecurityBundle\Util\TokenGenerator;

/**
 * @author Javier Sampedro <jsampedro77@gmail.com>
 */
class AccessTokenProvider
{
    private $redis;
    private $apikeyRepository;
    private $providerKey;
    private $fbToken = null;

    /**
     * "@snc_redis.default", "%MM_security.api.provider_key%"
     * @param ? $redis
     * @param ? $apikeyRepository
     * @param ? $providerKey
     */
    public function __construct($redis, $providerKey)
    {
        $this->redis = $redis;
        $this->providerKey = $providerKey;
    }

    /**
     * @param  string   $hash
     * @return ApiToken
     */
    public function fromHash($hash)
    {
        // try to recover api token from redis
        $token = $this->searchRedisHash($hash);

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

        if (!$hash || !$this->searchRedisHash($hash)) {
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
    protected function searchRedisHash($hash)
    {
        
        $data = $this->redis->get('nazka_security_token:' . $hash);
        if ($data) {
            $data = unserialize($data);
            $entity = $data['entity'];
            $apiToken = $this->createApiToken($entity, $data['roles']);

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
    protected function storeAccessToken($entity, $roles)
    {
        $data = array(
            'entity' => $entity,
            'roles' => $roles
        );

        $tokenGenerator = new TokenGenerator();
        $hashToken = $tokenGenerator->generateToken();

        //store hash in Redis
        $this->redis->set('nazka_security_token:' . $hashToken, serialize($data));


        return $hashToken;
    }

    /**
     * @param  object   $user
     * @param  array    $roles
     * @return ApiToken
     */
    protected function createApiToken($entity, $roles = array())
    {
        return new ApiToken($entity, $this->providerKey, $roles);
    }
}
