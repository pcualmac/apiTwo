<?php
namespace Database\Factories\AppOne; // Update the namespace to match your model's namespace

use App\Models\AppOne\AppUser; // Update the namespace to match your model's namespace
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

class AppUserFactory extends Factory
{
    protected $model = AppUser::class;

    public function definition()
    {
        return [
            'name' => $this->faker->name,
            'email' => $this->faker->unique()->safeEmail,
            'email_verified_at' => now(),
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
            'remember_token' => Str::random(10),
        ];
    }
}