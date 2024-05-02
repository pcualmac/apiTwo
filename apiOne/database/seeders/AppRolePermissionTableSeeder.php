<?php

namespace Database\Seeders;
use Illuminate\Database\Seeder;
use App\Models\Application;
use App\Models\Role;
use App\Models\Permission;
use App\Models\AppRolePermission;
use App\Models\AppOne\AppUser;

class AppRolePermissionTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {

        $users = AppUser::all();
        $permission = Permission::all();
        $roles = Role::all();
        $application = Application::all();

        foreach ($users as $user) {
            $randomRoles = $roles->random()->id;
            $randomPermission = $permission->random()->id;
            AppRolePermission::firstOrCreate([
                'role_id' => $randomRoles, 
                'permission_id' => $randomPermission, 
                'application_id' => 1
            ]);
        }

    }
}
