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
    public function findHash($hash);
    
    public function storeHash($hash, UserInterface $user, array $roles);
    
    public function findUserAccessToken(UserInterface $user);
}