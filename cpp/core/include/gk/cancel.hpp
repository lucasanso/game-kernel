// Cooperative cancellation / pause token shared between the orchestrator and analysis code.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace gk {

class CancelToken {
public:
    void cancel() noexcept {
        cancelled_.store(true, std::memory_order_release);
        std::lock_guard lock(mutex_);
        cv_.notify_all();
    }
    void pause() noexcept { paused_.store(true, std::memory_order_release); }
    void resume() noexcept {
        paused_.store(false, std::memory_order_release);
        std::lock_guard lock(mutex_);
        cv_.notify_all();
    }
    [[nodiscard]] bool cancelled() const noexcept { return cancelled_.load(std::memory_order_acquire); }
    [[nodiscard]] bool paused() const noexcept { return paused_.load(std::memory_order_acquire); }

    // Blocks while paused. Returns false if cancelled (caller must stop).
    bool wait_if_paused() {
        if (!paused()) return !cancelled();
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this] { return !paused() || cancelled(); });
        return !cancelled();
    }

private:
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> paused_{false};
    std::mutex mutex_;
    std::condition_variable cv_;
};

}  // namespace gk
