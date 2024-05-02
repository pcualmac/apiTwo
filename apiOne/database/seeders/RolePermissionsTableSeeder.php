<?php

namespace Database\Seeders;
use Illuminate\Database\Seeder;
// use Spatie\Permission\Models\Role;
// use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\DB;


class RolePermissionsTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Define role-permission mappings
        $rolePermissions = [
            ['role_id' => 1, 'permission_id' => 1], // Admin App1 Create Post
            ['role_id' => 1, 'permission_id' => 2], // Admin App1 Edit Post
            ['role_id' => 2, 'permission_id' => 1], // User App1 Create Post
            ['role_id' => 3, 'permission_id' => 1], // Admin App2 Create Post
            ['role_id' => 3, 'permission_id' => 2], // Admin App2 Edit Post
            // Add more role-permission mappings as needed
        ];

        // Insert data into the RolePermissionTable
        foreach ($rolePermissions as $rolePermission) {
            DB::table('role_permissions')->insert($rolePermission);
        }
    }
}
