<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Permission;

class PermissionsTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Permission::create(['name' => 'Create Post', 'slug' => 'create_post', 'description' => 'Create new post']);
        Permission::create(['name' => 'Edit Post', 'slug' => 'edit_post', 'description' => 'Edit existing post']);
    }
}
