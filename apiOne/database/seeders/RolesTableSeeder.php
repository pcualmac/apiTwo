<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Role;

class RolesTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Role::create([
            'name' => 'Admin App1', 
            'slug' => 'admin-app1', 
            'description' => 'Administrator',
        ]);
        Role::create([
            'name' => 'User App1', 
            'slug' => 'user-app1', 
            'description' => 'Regular User',
        ]);
        Role::create([
            'name' => 'Admin App2', 
            'slug' => 'admin-app2', 
            'description' => 'Administrator',
        ]);
        Role::create([
            'name' => 'User App2', 
            'slug' => 'user-app1-2', 
            'description' => 'Regular User',
        ]);
    }
}
