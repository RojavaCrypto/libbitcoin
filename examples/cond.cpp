#include <array>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

size_t columns_size = 20;

std::condition_variable condition;
std::mutex mutex;
std::array<bool, 4> workers_ready = { false, false, false, false };
size_t stuff_index = 0;
bool finished = false;

void worker(size_t row, std::function<void (size_t, size_t)> perform_compute)
{
    std::cout << "Thread dispatched: " << row << std::endl;
    size_t current_index;
    while (true)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            condition.wait(lock, [&]{ return workers_ready[row]; });
            current_index = stuff_index;
            lock.unlock();
        }

        // Perform our unique calculation
        perform_compute(row, current_index);

        {
            std::unique_lock<std::mutex> lock(mutex);
            workers_ready[row] = false;
            condition.notify_all();
            lock.unlock();
        }

        // Last item so stop waiting...
        if (current_index == columns_size - 1)
            break;
    }
}

int main()
{
    auto compute = [&](size_t row, size_t current_index)
    {
        if (row == 1)
            std::cout << row << ":" << current_index << std::endl;
        std::this_thread::sleep_for(1s);
    };

    std::vector<std::thread> threads;
    threads.push_back(std::thread(worker, 0, compute));
    threads.push_back(std::thread(worker, 1, compute));
    threads.push_back(std::thread(worker, 2, compute));
    threads.push_back(std::thread(worker, 3, compute));

    for (size_t i = 0; i < columns_size; ++i)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            stuff_index = i;
            workers_ready = { true, true, true, true };
            condition.notify_all();
            lock.unlock();
        }
        {
            std::unique_lock<std::mutex> lock(mutex);
            condition.wait(lock, []{
                // All workers available for the next task...
                for (auto worker_state: workers_ready)
                    if (worker_state)
                        return false;
                return true;
            });
            lock.unlock();
        }

        // Use values calculated by workers
        std::cout << "Here!" << std::endl;
        std::this_thread::sleep_for(1s);
    }

    for (auto& thread: threads)
        thread.join();

    return 0;
}

