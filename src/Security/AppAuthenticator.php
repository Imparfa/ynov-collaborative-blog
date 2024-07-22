<?php

namespace App\Security;

use Psr\Log\LoggerInterface;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class AppAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    private RouterInterface $router;

    public function __construct(RouterInterface $router, private readonly LoggerInterface $logger)
    {
        $this->router = $router;
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->router->generate(self::LOGIN_ROUTE);
    }

    public function authenticate(Request $request): Passport
    {
        $username = $request->request->get('email', '');

        return new Passport(
            new UserBadge($username),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
            ]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->router->generate('home'));
    }

    public function supports(Request $request): bool
    {
//        $request->setMethod('POST');
//        $this->logger->info("---------------------------------");
//        $this->logger->info("Request: " . $request->attributes->get('_route'));
//        $this->logger->info("Method: " . $request->getMethod());
//        $this->logger->info("Login Route " .  self::LOGIN_ROUTE);
//        $this->logger->info("Is Login Route: " . (self::LOGIN_ROUTE === $request->attributes->get('_route') && $request->isMethod('POST') ? "true" : "false"));
//        $this->logger->info("---------------------------------");
//        if ($request->attributes->get('_route') === self::LOGIN_ROUTE)
//            return $request->isMethod('POST');
//        else
//            return true;

        return self::LOGIN_ROUTE === $request->attributes->get('_route') && $request->isMethod('POST');
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->getLoginUrl($request));
    }
}

//    $this->logger->info("---------------------------------");
//    $this->logger->info("Request: " . $request->attributes->get('_route'));
//    $this->logger->info("Method: " . $request->getMethod());
//    $this->logger->info("Login Route " .  self::LOGIN_ROUTE);
//    $this->logger->info("Is Login Route: " . (self::LOGIN_ROUTE === $request->attributes->get('_route')));
//    $this->logger->info("---------------------------------");