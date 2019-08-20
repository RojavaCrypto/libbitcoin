#include <atomic>
#include <bitcoin/system.hpp>
namespace bcs = bc::system;

int main()
{
	auto max_threads = std::thread::hardware_concurrency();
    std::cout << "Starting " << max_threads << " threads." << std::endl;

    bcs::asio::service service;
    std::atomic<size_t> count = 0;

    for (size_t j = 0; j < 100; ++j)
    {
        auto compute = [&]()
        {
            --count;
        };

        service.post(compute);
        ++count;
    }

    std::cout << "Starting worker threads..." << std::endl;
    std::vector<bcs::asio::thread> threads;
    for (size_t i = 0; i < max_threads; ++i)
        threads.push_back(bcs::asio::thread([&service]()
        {
            bcs::set_priority(bcs::thread_priority::high);
            service.run();
        }));

    std::cout << "Joining..." << std::endl;
    for (auto& thread: threads)
    {
        BITCOIN_ASSERT(thread.joinable());
        thread.join();
    }

    std::cout << std::endl;
    std::cout << "count = " << count << std::endl;
    BITCOIN_ASSERT(count == 0);

    return 0;
}

