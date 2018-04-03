<?php

namespace Dorcyv\JwtSessionBundle\EventSubscriber;

use Dorcyv\JwtSessionBundle\Cookie\CookieManager;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Class CookieEventSubscriber
 */
class CookieEventSubscriber implements EventSubscriberInterface
{
    /**
     * @var CookieManager
     */
    private $cookieManager;

    /**
     * CookieEventSubscriber constructor.
     *
     * @param CookieManager $cookieManager
     */
    public function __construct(CookieManager $cookieManager)
    {
        $this->cookieManager = $cookieManager;
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST  => ['onKernelRequest', 130],
            KernelEvents::RESPONSE => ['onKernelResponse', -1048]
        ];
    }

    /**
     * @param GetResponseEvent $event
     *
     * @return Request
     *
     * @throws \InvalidArgumentException
     */
    public function onKernelRequest(GetResponseEvent $event): Request
    {
        $request = $event->getRequest();

        /** @var Cookie $cookie */
        foreach ($request->cookies->all() as $name => $value) {
            $cookie = new Cookie($name, $value);
            $this->cookieManager->addCookie($cookie);
        }

        return $request;
    }

    /**
     * @param FilterResponseEvent $event
     *
     * @return Response
     */
    public function onKernelResponse(FilterResponseEvent $event): Response
    {
        $response = $event->getResponse();
        foreach ($this->cookieManager->getCookies() as $cookie) {
            $response->headers->setCookie($cookie);
        }

        return $response;
    }
}
