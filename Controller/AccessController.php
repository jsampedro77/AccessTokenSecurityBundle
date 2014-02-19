<?php

namespace Nazka\AccessTokenSecurityBundle\Controller;

use FOS\RestBundle\Controller\FOSRestController;
use FOS\RestBundle\Request\ParamFetcher;
use FOS\RestBundle\Controller\Annotations as Rest;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Nelmio\ApiDocBundle\Annotation\ApiDoc;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * @Rest\RouteResource("AccessToken")
 */
class AccessController extends FOSRestController
{

    /**
     * Validates user password combinations and returns and accessToken
     *
     * @ApiDoc(
     *     section="Login",
     *     resource=false,
     *     description="Get an Access Token for Username/Password",
     *     statusCodes={
     *         200="Returned when Successful login",
     *         404={
     *             "Returned when Username/Password combination is invalid",
     *         }
     *     }
     * )
     *
     * @Rest\QueryParam(name="username", strict=true, nullable=false, description="Username")
     * @Rest\QueryParam(name="password", strict=true, nullable=false, description="Plain password")
     * @Rest\View(serializerGroups={"profile"})
     */
    public function getAction(ParamFetcher $paramFetcher)
    {
        $loginAuthenticationManager = $this->get('nazka_accesstoken_security.usernamepassword.login.manager');

        try {
            $user = $loginAuthenticationManager->checkLogin($paramFetcher->get('username'), $paramFetcher->get('password'));
            $accessToken = $this->getAuthenticationManager()->getAccessTokenForUser($user);
        } catch (\Exception $e) {
            throw new AccessDeniedHttpException($e->getMessage());
        }

        return array(
            'id' => $user->getId(),
            'access_token' => $accessToken
        );
    }

    protected function getAuthenticationManager()
    {
        return $this->get('nazka_accesstoken_security.authentication.manager');
    }
}
