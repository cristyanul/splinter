#include "profiles.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "config.h"

static const char *TAG = "splinter-profiles";

// Runtime "breathing" density multiplier as fixed-point x100 (100 = 1.0x, the
// densest/base rate; higher = sparser). The decoy tasks read this to stretch
// their inter-frame pacing. Profiles NEVER writes back into the persisted
// config, so the user's configured base intervals stay intact and the web UI
// always reflects real values (no drift across save/reboot cycles).
static volatile uint32_t s_mult_x100 = 100;

uint32_t profiles_density_x100(void) { return s_mult_x100; }

uint32_t profiles_scale_interval(uint32_t base_ms, uint32_t min_ms)
{
    uint64_t scaled = (uint64_t)base_ms * s_mult_x100 / 100u;
    if (scaled < min_ms) scaled = min_ms;
    if (scaled > 60000u) scaled = 60000u; // clamp to a sane ceiling
    return (uint32_t)scaled;
}

// Runs unconditionally (cheap idle when disabled) so the profiles toggle takes
// effect live from the web UI without a reboot.
static void profiles_task(void *arg)
{
    ESP_LOGI(TAG, "Dynamic profiles (breathing) task started");
    double current = 1.0;
    double target  = 1.0;

    for (;;) {
        const splinter_cfg_t *cfg = config_get();
        if (!cfg->profiles_enabled) {
            // Hold at base density and reset the walk so re-enabling glides
            // smoothly from 1.0 instead of snapping to a stale target.
            s_mult_x100 = 100;
            current = 1.0;
            target  = 1.0;
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }

        // Occasionally pick a new target density between 1.0 (dense) and 3.0 (sparse).
        if (esp_random() % 100 < 5) {
            target = 1.0 + (esp_random() % 201) / 100.0; // 1.00 .. 3.00
        }

        // Low-pass filter glides smoothly toward the target (no abrupt jumps).
        current += 0.05 * (target - current);

        uint32_t m = (uint32_t)(current * 100.0 + 0.5);
        if (m < 100) m = 100;
        s_mult_x100 = m;

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void profiles_start(void)
{
    xTaskCreate(profiles_task, "splinter_prof", 3072, NULL, 3, NULL);
}
