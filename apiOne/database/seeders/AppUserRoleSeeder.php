<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class AppUserRoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // Example data
        $data = [
            [
                'app_user_id' => 1,
                'role_id' => 1,
                'application_id' => 1,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'app_user_id' => 2,
                'role_id' => 2,
                'application_id' => 1,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            // Add more data as needed
        ];

        // Insert data into the table
        DB::table('app_user_role')->insert($data);
    }
}
