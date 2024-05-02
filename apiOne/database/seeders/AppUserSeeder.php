<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\AppOne\AppUser; // Make sure to import the correct namespace
use Database\Factories\AppOne\AppUserFactory; // Correct the namespace for the factory

class AppUserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        AppUser::factory(10)->create();

        AppUser::factory()->create([
            'name' => 'Test User',
            'email' => 'test@example.com',
        ]);
    }
}