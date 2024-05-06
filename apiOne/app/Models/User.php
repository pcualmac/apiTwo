<?php

namespace App\Models;

use App\Models\Role;
use App\Models\Permission;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Laravel\Sanctum\HasApiTokens;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Auth\User as Authenticatable;


class User extends Authenticatable implements ShouldQueue , JWTSubject
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'roles'
    ];

    protected $table = 'app_users';

    public function roles()
    {
        return $this->belongsToMany(Role::class)->wherePivot('application_id', 1);
    }

    public function scopeRole($query, $applicationId)
    {
        return $query->where('application_id', '=', $applicationId);
    }

    public function permissions()
    {
        $result = $this->hasManyThrough(Permission::class, Role::class);
        return $result->populationAbove(1);
    }

    public function hasRole($roleSlug)
    {
        return $this->roles()->where('slug', $roleSlug)->exists();
    }

    public function hasPermission($permissionSlug)
    {
        return $this->permissions()->where('slug', $permissionSlug)->exists();
    }

    // Assign role to user
    public function assignRole($role)
    {
        return $this->roles()->sync([$role]);
    }

    // Check if user has a certain permission
    public function hasPermissionTo($permission)
    {
        return $this->hasPermissionThroughRole($permission) || $this->hasPermission($permission);
    }

    // Check if user has a permission through role
    protected function hasPermissionThroughRole($permission)
    {
        foreach ($this->roles as $role) {
            if ($role->hasPermissionTo($permission)) {
                return true;
            }
        }
        return false;
    }

    public function getJWTIdentifier()
    {
        return $this->getKey(); // Assuming your admin model has a primary key called "id".
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
       // $result = $this->roles()->get();
        //return $result->toArray();
        return [];
    }
}