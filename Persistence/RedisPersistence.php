<?php

namespace Nazka\AccessTokenSecurityBundle\Persistence;

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

    public function findHash($hash)
    {
        $data = $this->redis->get('nazka_security_token:' . $hash);

        if ($data) {
            unserialize($data);

            return array($data['user'], $data['roles']);
        }

        return null;
    }

    public function storeHash($hash, $user, $roles)
    {
        $data = array(
            'user' => $user,
            'roles' => $roles
        );
        
        return $this->redis->set('nazka_security_token:' . $hashToken, serialize($data));
    }
}
