<?php

namespace Nazka\AccessTokenSecurityBundle\Security\Firewall;

use Nazka\AccessTokenSecurityBundle\Security\Authentication\Token\ApiToken;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;

class ApiListener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;
    protected $providerKey;

    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, $providerKey)
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $authToken = new ApiToken('not auth.', $this->providerKey);
        $authToken->accessToken = $request->headers->get('AccessToken');

        if ($authToken = $this->authenticationManager->authenticate($authToken)) {
            $this->securityContext->setToken($authToken);
        } else {
            $anonymousToken = new AnonymousToken($this->providerKey, 'anonymous');
            $this->securityContext->setToken($anonymousToken);
        }

        return;
    }
}
