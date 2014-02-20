<?php

namespace Nazka\AccessTokenSecurityBundle\Persistence;

use Symfony\Component\Security\Core\User\UserInterface;
/**
 * Define methods to have access token persistence
 *
 * @author javier
 */
interface PersistenceInterface
{
    /**
     * Provide a hash token and find the related User,
     * 
     * @return Symfony\Component\Security\Core\User\UserInterface, ROLES array
     */
    public function findUserByHash($hash);
    
    /**
     * Store an UserInterface and ROLES array
     */
    public function storeHash($hash, UserInterface $user, array $roles);
    
    /**
     * Find and AccessToken
     */
    public function findHashByUser(UserInterface $user);
}