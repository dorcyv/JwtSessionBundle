<?php

/**
 * This file is part of the JwtSessionBundle package.
 *
 * (c) Valérian Dorcy <valerian.dorcy@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 */

namespace Dorcyv\JwtSessionBundle\Cookie;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Class CookieManager
 */
class CookieManager
{
    /**
     * @var Collection
     */
    private $cookies;

    /**
     * CookieManager constructor.
     */
    public function __construct()
    {
        $this->cookies = new ArrayCollection();
    }

    /**
     * @param Cookie $cookie
     */
    public function addCookie(Cookie $cookie): void
    {
        $this->removeCookie($cookie->getName());
        $this->cookies->add($cookie);
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function removeCookie(string $name): bool
    {
        foreach ($this->cookies as $cookie) {
            if ($cookie->getName() === $name) {
                return $this->cookies->removeElement($cookie);
            }
        }

        return false;
    }

    /**
     * @param string $name
     *
     * @return null|Cookie
     */
    public function getCookie(string $name): ?Cookie
    {
        /** @var Cookie $cookie */
        foreach ($this->cookies as $cookie) {
            if ($cookie->getName() === $name) {
                return $cookie;
            }
        }

        return null;
    }

    /**
     * @return Collection
     */
    public function getCookies(): Collection
    {
        return $this->cookies;
    }
}
