<?php

/*
 * This file is part of SeAT
 *
 * Copyright (C) 2015 to present Leon Jacobs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

namespace Seat\Eseye\Access;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Seat\Eseye\Checker\EsiTokenValidator;
use Seat\Eseye\Configuration;
use Seat\Eseye\Containers\EsiAuthentication;
use Seat\Eseye\Containers\EsiResponse;
use Seat\Eseye\Eseye;
use Seat\Eseye\Exceptions\DiscoverServiceNotAvailableException;
use Seat\Eseye\Exceptions\InvalidAuthenticationException;
use Seat\Eseye\Exceptions\InvalidContainerDataException;
use Seat\Eseye\Exceptions\RequestFailedException;

class AccessTokenRefresher implements AccessTokenRefresherInterface
{
    /**
     * @var StreamFactoryInterface
     */
    private StreamFactoryInterface $stream_factory;

    /**
     * @var RequestFactoryInterface
     */
    private RequestFactoryInterface $request_factory;

    /**
     * @var string
     */
    protected string $sso_base;

    /**
     * @var ClientInterface
     */
    protected ClientInterface $client;

    /**
     * @var LoggerInterface
     */
    protected LoggerInterface $logger;

    /**
     * @var EsiTokenValidator
     */
    protected EsiTokenValidator $jwt_validator;

    /**
     * @throws InvalidContainerDataException
     */
    public function __construct()
    {
        // Init the logger
        $this->logger = Configuration::getInstance()->getLogger();

        $this->client = Configuration::getInstance()->getHttpClient();
        $this->stream_factory = Configuration::getInstance()->getHttpStreamFactory();
        $this->request_factory = Configuration::getInstance()->getHttpRequestFactory();

        // Init SSO base URI
        $this->sso_base = sprintf('%s://%s:%d/v2/oauth',
            Configuration::getInstance()->sso_scheme,
            Configuration::getInstance()->sso_host,
            Configuration::getInstance()->sso_port);

        // Init JWT validator
        $this->jwt_validator = new EsiTokenValidator();
    }

    /**
     * @throws DiscoverServiceNotAvailableException
     * @throws InvalidContainerDataException
     * @throws RequestFailedException
     * @throws ClientExceptionInterface
     * @throws InvalidAuthenticationException
     */
    public function getValidAccessToken(EsiAuthentication $authentication): EsiAuthentication
    {
        // Check the expiry date.
        $expires = carbon($authentication->token_expires);

        // If the token expires in the next minute, refresh it.
        if ($expires->lte(carbon('now')->addMinute())) {
            $authentication = $this->refreshToken($authentication);
        }

        return $authentication;
    }

    /**
     * Refresh the Access token that we have in the EsiAccess container.
     *
     * @throws InvalidContainerDataException
     * @throws ClientExceptionInterface
     * @throws RequestFailedException
     * @throws DiscoverServiceNotAvailableException
     * @throws InvalidAuthenticationException
     */
    private function refreshToken(EsiAuthentication $authentication): EsiAuthentication
    {
        // Make the post request for a new access_token
        $stream = $this->stream_factory->createStream($this->getRefreshTokenForm($authentication));

        $request = $this->request_factory->createRequest('POST', $this->sso_base . '/token')
            ->withHeader('Authorization', $this->getBasicAuthorizationHeader($authentication))
            ->withHeader('User-Agent', 'Eseye/' . Eseye::VERSION . '/' . Configuration::getInstance()->http_user_agent)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($stream);

        $response = $this->client->sendRequest($request);

        // Grab the body from the StreamInterface instance.
        $content = $response->getBody()->getContents();

        // Client or Server Exception
        if ($response->getStatusCode() >= 400 && $response->getStatusCode() < 600) {
            // Log the event as failed
            $this->logger->error('[http ' . $response->getStatusCode() . ', ' .
                strtolower($response->getReasonPhrase()) . '] ' .
                'get -> ' . $this->sso_base . '/token'
            );

            // For debugging purposes, log the response body
            $this->logger->debug('Request for get -> ' . $this->sso_base . '/token failed. Response body was: ' .
                $content);

            // Raise the exception that should be handled by the caller
            throw new RequestFailedException(new EsiResponse(
                $content,
                $response->getHeaders(),
                'now',
                $response->getStatusCode())
            );
        }

        $json = json_decode($content);

        $claims = $this->jwt_validator->validateToken($authentication->client_id, $json->access_token);
        $this->logger->debug('Successfully validate delivered token', [
            'claims' => $claims,
        ]);

        // Set the new authentication values from the request
        $authentication->access_token = $json->access_token;
        $authentication->refresh_token = $json->refresh_token;
        $authentication->token_expires = $claims['exp'];
        $authentication->scopes = $claims['scp'];

        return $authentication;
    }

    /**
     * @param  EsiAuthentication  $authentication
     * @return string
     */
    private function getRefreshTokenForm(EsiAuthentication $authentication): string
    {
        $form = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $authentication->refresh_token,
        ];

        return http_build_query($form);
    }

    /**
     * @return string
     */
    private function getBasicAuthorizationHeader(EsiAuthentication $authentication): string
    {
        return 'Basic ' . base64_encode($authentication->client_id . ':' . $authentication->secret);
    }
}
