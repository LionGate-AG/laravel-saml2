<?php

namespace Slides\Saml2\Http\Middleware;

use Slides\Saml2\Repositories\TenantRepository;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Slides\Saml2\OneLoginBuilder;

/**
 * Class ResolveTenant
 *
 * @package Slides\Saml2\Http\Middleware
 */
class ResolveTenant
{
    /**
     * @var TenantRepository
     */
    protected $tenants;

    /**
     * @var OneLoginBuilder
     */
    protected $builder;

    /**
     * ResolveTenant constructor.
     *
     * @param TenantRepository $tenants
     * @param OneLoginBuilder $builder
     */
    public function __construct(TenantRepository $tenants, OneLoginBuilder $builder)
    {
        $this->tenants = $tenants;
        $this->builder = $builder;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     *
     * @throws NotFoundHttpException
     *
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        if (!$tenant = $this->resolveTenant($request)) {
            throw new NotFoundHttpException();
        }

        if (config('saml2.debug')) {
            Log::debug('[Saml2] Tenant resolved', [
                'uuid' => $tenant->uuid,
                'id' => $tenant->id,
                'key' => $tenant->key
            ]);
        }

        session()->flash('saml2.tenant.uuid', $tenant->uuid);

        $this->builder
            ->withTenant($tenant)
            ->bootstrap();

        return $next($request);
    }

    /**
     * Resolve a tenant by a request.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Slides\Saml2\Models\Tenant|null
     */
    protected function resolveTenant($request)
    {
        if (!$uuidOrKey = $request->route('uuid')) {
            if (config('saml2.debug')) {
                Log::debug('[Saml2] Tenant UUID or key is not present in the URL so cannot be resolved', [
                    'url' => $request->fullUrl()
                ]);
            }

            return null;
        }

        //Technically, we may get multiple tenants (aka. a collection) when querying by any identifier
        $tenant = $this->tenants->findByAnyIdentifier($uuidOrKey, true);

        //if(!$tenant = $this->tenants->findByUUID($uuid)) {
        if ($tenant->count() === 0) {
            if (config('saml2.debug')) {
                Log::debug('[Saml2] Tenant doesn\'t exist', [
                    'uuidOrKey' => $uuidOrKey
                ]);
            }

            return null;
        }

        if ($tenant->count() > 1) {
            if (config('saml2.debug')) {
                Log::debug('[Saml2] Tenant is not unique', [
                    'uuidOrKey' => $uuidOrKey
                ]);
            }

            return null;
        }

        //We definitely found exactly one tenant once we get here
        $tenant = $tenant->first();

        if ($tenant->trashed()) {
            if (config('saml2.debug')) {
                Log::debug('[Saml2] Tenant #' . $tenant->id . ' resolved but marked as deleted', [
                    'id' => $tenant->id,
                    'uuidOrKey' => $uuidOrKey,
                    'deleted_at' => $tenant->deleted_at->toDateTimeString()
                ]);
            }

            return null;
        }

        return $tenant;
    }
}
