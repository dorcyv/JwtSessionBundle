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

namespace Dorcyv\JwtSessionBundle\Jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

/**
 * Class JwtWrapper
 */
class JwtWrapper
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var string
     */
    private $jwtSecret;

    /**
     * @var string
     */
    private $issuer;

    /**
     * JwtWrapper constructor.
     *
     * @param string $jwtSecret
     * @param string $issuer
     */
    public function __construct(string $jwtSecret, string $issuer)
    {
        $this->jwtSecret = $jwtSecret;
        $this->signer = new Sha256();
        $this->issuer = $issuer;
    }

    /**
     * @return Token
     */
    public function createToken(): Token
    {
        $builder = new Builder();
        $builder->setIssuer($this->issuer);
        $this->sign($builder);

        return $builder->getToken();
    }

    /**
     * @param Builder $builder
     */
    private function sign(Builder $builder): void
    {
        $builder->sign($this->signer, $this->jwtSecret);
    }

    /**
     * @param string $token
     *
     * @return bool
     */
    public function isJwtToken(string $token): bool
    {
        return $this->parse($token) !== null;
    }

    /**
     * @param string $token
     *
     * @return Token
     */
    public function parse(string $token): Token
    {
        try {
            $parser = new Parser();

            return $parser->parse($token);
        } catch (\Exception $exception) {
            return null;
        }
    }

    /**
     * @param Token $token
     *
     * @return bool
     *
     * @throws \BadMethodCallException
     */
    public function isValid(Token $token): bool
    {
        $data = new ValidationData(\time());
        $data->setIssuer($this->issuer);

        return $token->verify($this->signer, $this->jwtSecret) && $token->validate($data);
    }

    /**
     * @param Token $token
     * @param int   $exp
     *
     * @return Token
     *
     * @throws \BadMethodCallException
     */
    public function updateExpiration(Token $token, int $exp): Token
    {
        return $this->updateClaim($token, 'exp', $exp);
    }

    /**
     * @param Token  $token
     * @param string $name
     * @param string $value
     *
     * @return Token
     *
     * @throws \BadMethodCallException
     */
    public function updateClaim(Token $token, string $name, string $value): Token
    {
        $builder = $this->getBuilder($token);
        $builder->set($name, $value);
        $this->sign($builder);

        return $builder->getToken();
    }

    /**
     * @param Token $token
     *
     * @return Builder
     *
     * @throws \BadMethodCallException
     */
    private function getBuilder(Token $token): Builder
    {
        $builder = new Builder();
        foreach ($token->getHeaders() as $headerName => $headerValue) {
            $builder->setHeader($headerName, $headerValue);
        }
        foreach ($token->getClaims() as $claimName => $claimValue) {
            $builder->set($claimName, $claimValue);
        }

        return $builder;
    }
}
