<?php

namespace Nazka\AccessTokenSecurityBundle\Persistence;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Description of RedisPersistence
 *
 * @author javier
 */
class RedisPersistence implements PersistenceInterface
{

    protected $redis;

    public function __construct($redis)
    {
        $this->redis = $redis;
    }

    public function findUserByHash($hash)
    {
        $data = $this->redis->get('nazka_security_token:' . $hash);

        if ($data) {
            $data = unserialize($data);

            return array($data['user'], $data['roles']);
        }

        return null;
    }

    public function storeHash($hash, UserInterface $user, array $roles)
    {
        $data = array(
            'user' => $user,
            'roles' => $roles
        );

        // store hash in so we can find it on user login.
        $this->redis->setex($this->getUserCacheRedisKey($user->getId()), 3600, $hash);

        return $this->redis->set('nazka_security_token:' . $hash, serialize($data));
    }

    public function findHashByUser(UserInterface $user)
    {
        return $this->redis->get($this->getUserCacheRedisKey($user->getId()));
    }

    private function getUserCacheRedisKey($userId)
    {
        return 'nazka_security_user:' . $userId;
    }
}
