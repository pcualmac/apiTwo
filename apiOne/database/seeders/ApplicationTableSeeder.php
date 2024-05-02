<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Application;
use Illuminate\Support\Facades\Config;

class ApplicationTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Application::create(['name' => 'appone', 'url' => 'http://192.168.255.1:8080', 'jwt_private_key' => Config::get('app_tokens.application1')]);
        Application::create(['name' => 'appTwo', 'url' => 'http://192.168.255.1:8085', 'jwt_private_key' => Config::get('app_tokens.application2')]);
    }
}
