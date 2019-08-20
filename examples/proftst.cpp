#include <condition_variable>
#include <future>
#include <thread>
#include <bitcoin/system.hpp>
#include <blake2.h>

namespace bcs = bc::system;

const bcs::ec_point G = bcs::ec_compressed{ 0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };

using scalar_list = std::vector<bcs::ec_scalar>;
using scalar_table = std::vector<scalar_list>;
using point_list = std::vector<bcs::ec_point>;
using point_ring = std::vector<point_list>;

scalar_table salts;
scalar_list challenges;
point_ring publics;
point_ring hashed_publics;
point_list key_images;
point_ring left_points;
point_ring right_points;

size_t rows_size = 0, columns_size = 0;

void initialize()
{
    std::ifstream infile("data.bin");

    auto read_uint = [&]()
    {
        bcs::byte_array<8> data;
        infile.read(reinterpret_cast<char*>(data.data()), data.size());
        return bcs::from_big_endian<uint64_t>(data.begin(), data.end());
    };

    auto read_scalar = [&]()
    {
        bcs::ec_secret secret;
        infile.read(reinterpret_cast<char*>(secret.data()), secret.size());
        return bcs::ec_scalar(secret);
    };

    auto read_point = [&]()
    {
        bcs::ec_compressed point;
        infile.read(reinterpret_cast<char*>(point.data()), point.size());
        return bcs::ec_point(point);
    };

    rows_size = read_uint();
    columns_size = read_uint();
    std::cout << "rows = " << rows_size << ", "
        << "columns = " << columns_size << std::endl;

    for (size_t i = 0; i < rows_size; ++i)
    {
        scalar_list row;
        for (size_t j = 0; j < columns_size; ++j)
            row.push_back(read_scalar());
        salts.push_back(row);
    }

    for (size_t j = 0; j < columns_size; ++j)
        challenges.push_back(read_scalar());

    for (size_t i = 0; i < rows_size; ++i)
    {
        point_list row;
        for (size_t j = 0; j < columns_size; ++j)
            row.push_back(read_point());
        publics.push_back(row);
    }

    for (size_t i = 0; i < rows_size; ++i)
    {
        point_list row;
        for (size_t j = 0; j < columns_size; ++j)
            row.push_back(read_point());
        hashed_publics.push_back(row);
    }

    for (size_t i = 0; i < rows_size; ++i)
        key_images.push_back(read_point());

    for (size_t i = 0; i < rows_size; ++i)
    {
        point_list row;
        for (size_t j = 0; j < columns_size; ++j)
            row.push_back(read_point());
        left_points.push_back(row);
    }

    for (size_t i = 0; i < rows_size; ++i)
    {
        point_list row;
        for (size_t j = 0; j < columns_size; ++j)
            row.push_back(read_point());
        right_points.push_back(row);
    }

    auto convert_scalar = [](const auto& scalar)
    {
        return bcs::encode_base16(scalar.secret());
    };
    auto convert_point = [](const auto& point)
    {
        return bcs::encode_base16(point.point());
    };

    std::cout << "rows = " << rows_size << ", "
        << "columns = " << columns_size << std::endl;
    std::cout << "salt[0][110] = "
        << convert_scalar(salts[0][110]) << std::endl;
    std::cout << "challenges[110] = "
        << convert_scalar(challenges[110]) << std::endl;
    std::cout << "publics[0][110] = "
        << convert_point(publics[0][110]) << std::endl;
    std::cout << "hashed_publics[0][110] = "
        << convert_point(hashed_publics[0][110]) << std::endl;
    std::cout << "key_images[0] = "
        << convert_point(key_images[0]) << std::endl;
    std::cout << "left_points[0][110] = "
        << convert_point(left_points[0][110]) << std::endl;
    std::cout << "right_points[0][110] = "
        << convert_point(right_points[0][110]) << std::endl;
}

bcs::ec_scalar borromean_hash(
    const point_ring& left, const point_ring& right, uint32_t index)
{
    BITCOIN_ASSERT(bcs::hash_size == BLAKE2S_OUTBYTES);
    bcs::ec_secret hash;
    const auto& data = left[0][index].point();
    const auto out = blake2s(hash.data(), data.data(), NULL,
        BLAKE2S_OUTBYTES, data.size(), 0);
    BITCOIN_ASSERT(out == 0);
    return hash;

    //return bcs::sha256_hash(left[0][index].point());

    //BITCOIN_ASSERT(left.size() == right.size());
    //bcs::data_chunk input_data;
    //for (size_t i = 0; i < left.size(); ++i)
    //{
    //    bcs::extend_data(input_data, left[i][index].point());
    //    bcs::extend_data(input_data, right[i][index].point());
    //}

    //// e = H(M || R || i )
    //bcs::data_chunk data(
    //    input_data.size() + sizeof(uint32_t));
    //auto serial = bcs::make_unsafe_serializer(data.begin());
    //serial.write_bytes(input_data);
    //serial.write_4_bytes_big_endian(index);
    //return bcs::sha256_hash(data);
}

void prepare_points()
{
	auto max_threads = std::thread::hardware_concurrency();
    std::cout << "Starting " << max_threads << " threads." << std::endl;

    bcs::asio::service service;
    std::atomic<size_t> count = 0;

    std::cout << "Prepare..." << std::endl;
    for (size_t j = 0; j < columns_size - 1; ++j)
    {
        for (size_t i = 0; i < rows_size; ++i)
        {
            auto compute_left = [&, i, j]()
            {
                --count;
                if (i == 0)
                    if (count % 100 == 0)
                        std::cout << j << "... " << std::flush;

                left_points[i][j] = salts[i][j] * G;
            };
            auto compute_right = [&, i, j]()
            {
                --count;
                //if (count % 100 == 0)
                //    std::cout << j << "... " << std::flush;

                right_points[i][j] = salts[i][j] * hashed_publics[i][j];
            };

            service.post(compute_left);
            service.post(compute_right);

            count += 2;

            ////// L = sG + cP
            //left_points[i][j] = salts[i][j] * G;
            ////// R = sH(P) + cI
            //right_points[i][j] = salts[i][j] * hashed_publics[i][j];
        }

    }
    std::cout << std::endl;

    std::vector<bcs::asio::thread> threads;
    for (size_t i = 0; i < max_threads; ++i)
        threads.push_back(bcs::asio::thread([&service]()
        {
            bcs::set_priority(bcs::thread_priority::high);
            service.run();
        }));
    std::cout << "joining..." << std::endl;
    for (auto& thread: threads)
    {
        BITCOIN_ASSERT(thread.joinable());
        thread.join();
    }

    std::cout << std::endl;
    std::cout << "count = " << count << std::endl;
    BITCOIN_ASSERT(count == 0);
}

std::condition_variable cv;
std::mutex cv_m; // This mutex is used for three purposes:
                 // 1) to synchronize accesses to i
                 // 2) to synchronize accesses to std::cerr
                 // 3) for the condition variable cv
int i = 0;
 
void waits()
{
    std::unique_lock<std::mutex> lk(cv_m);
    std::cerr << "Waiting... \n";
    cv.wait(lk, []{return i == 1;});
    std::cerr << "...finished waiting. i == 1\n";
}
 
void thing()
{
    std::thread t1(waits), t2(waits), t3(waits), t4(waits);

    sleep(4);
    {
        std::lock_guard<std::mutex> lk(cv_m);
        i = 1;
        std::cerr << "Notifying again...\n";
    }

    cv.notify_all();
    t1.join(); 
    t2.join(); 
    t3.join();
    t4.join();
}

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

void do_expensive_loop()
{
    auto compute_left = [&](size_t worker_id, size_t j)
    {
        //if (worker_id == 1)
        //    std::cout << worker_id << ":" << j << std::endl;
        //const auto i = worker_id % 2;
        left_points[i][j] =
            left_points[i][j] + challenges[j] * publics[i][j];
    };
    auto compute_right = [&](size_t worker_id, size_t j)
    {
        //const auto i = worker_id % 2;
        //std::cout << i << ":" << j << std::endl;
        right_points[i][j] =
            right_points[i][j] + challenges[j] * key_images[i];
    };

    std::vector<std::thread> threads;
    threads.push_back(std::thread(worker, 0, compute_left));
    threads.push_back(std::thread(worker, 1, compute_left));
    threads.push_back(std::thread(worker, 2, compute_right));
    threads.push_back(std::thread(worker, 3, compute_right));

    for (size_t j = 0; j < columns_size; ++j)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            stuff_index = j;
            workers_ready = { true, true, true, true };
            condition.notify_all();
            lock.unlock();
        }
        // Wait for jobs to finish...
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

        challenges[(j + 1) % columns_size] =
            borromean_hash(left_points, right_points, j);

        //if (j % 100 == 0)
        //    std::cout << j << "... " << std::flush;
    }
    std::cout << std::endl;
    std::cout << "Done" << std::endl;

    for (auto& thread: threads)
        thread.join();
}

void do_expensive_loop_old()
{
	auto max_threads = std::thread::hardware_concurrency();
    std::cout << "Starting " << max_threads << " threads." << std::endl;

    std::condition_variable condition;
    std::mutex mutex;

    int current_j = -1;

    auto update_left = [&](auto i)
    {
        std::cout << "Thread dispatched." << std::endl;
        int last_j = current_j;
        std::cout << i << ": j = " << last_j << std::endl;
        while (true)
        {
            std::unique_lock<std::mutex> lock(mutex);
            //std::cout << "Waiting: " << i << std::endl;
            condition.wait(lock, [&] {
                return current_j > last_j; });
            //std::cout << "Notified: " << i << std::endl;

            auto new_j = current_j;
            lock.unlock();

            last_j = new_j;
            ////////////
            for (auto j = last_j + 1; j <= new_j; ++j)
                left_points[i][j] =
                    left_points[i][j] + challenges[j] * publics[i][j];
            ////////////

            if (new_j == columns_size - 1 - 1)
            {
                std::cout << "Exiting: " << i
                    << " new_j = " << new_j << std::endl;
                return;
            }
        }
    };
    auto update_right = [&](auto i)
    {
        std::cout << "Thread dispatched." << std::endl;
        int last_j = current_j;
        std::cout << i << ": j = " << last_j << std::endl;
        while (true)
        {
            std::unique_lock<std::mutex> lock(mutex);
            //std::cout << "Waiting: " << i << std::endl;
            condition.wait(lock, [&] {
                return current_j > last_j; });
            //std::cout << "Notified: " << i << std::endl;

            auto new_j = current_j;
            lock.unlock();

            last_j = new_j;
            ////////////
            for (auto j = last_j + 1; j <= new_j; ++j)
            {
                std::cout << j << "... " << std::flush;
                right_points[i][j] =
                    right_points[i][j] + challenges[j] * key_images[i];
            }
            ////////////

            if (new_j == columns_size - 1 - 1)
            {
                std::cout << "Exiting: " << i
                    << " new_j = " << new_j << std::endl;
                return;
            }
        }
    };

    std::thread t1(update_left, 0);
    std::thread t2(update_left, 1);
    std::thread t3(update_right, 0);
    std::thread t4(update_right, 1);
    //auto update_right = [&](auto i)
    //{
    //    std::unique_lock<std::mutex> lock;
    //};

    //columns_size = 11;
    std::cout << "Expensive loop..." << std::endl;
    for (size_t j = 0; j < columns_size - 1; ++j)
    {
        //for (size_t i = 0; i < rows_size; ++i)
        {
            //auto compute_left = [&, i]()
            //{
            //    //left_points[i][j] =
            //    //    //left_points[i][j] + challenges[j] * publics[i][j];
            //    //    left_points[i][j] + publics[i][j];
            //};
            //auto compute_right = [&, i]()
            //{
            //    //right_points[i][j] =
            //    //    //right_points[i][j] + challenges[j] * key_images[i];
            //    //    right_points[i][j] + key_images[i];
            //};

            //// L = sG + cP
            //left_points[i][j] =
            //    left_points[i][j] + challenges[j] * publics[i][j];
            //// R = sH(P) + cI
            //right_points[i][j] =
            //    right_points[i][j] + challenges[j] * key_images[i];
        }
        //sleep(1);

        //std::cout << j << "... " << std::flush;
        //std::cout << std::endl;

        std::unique_lock<std::mutex> lock(mutex);
        current_j = j;
        lock.unlock();
        condition.notify_all();
        //std::cout << std::endl;

        //challenges[j + 1] = borromean_hash(left_points, right_points, j);

        //if (j % 100 == 0)
        //    std::cout << j << "... " << std::flush;
    }
    std::cout << std::endl;

    t1.join();
    t2.join();
    t3.join();
    t4.join();
}

int main()
{
    initialize();

    bcs::timer time;

    auto duration = time.execution(prepare_points);
    std::cout << std::endl;
    std::cout << duration << " ms" << std::endl;
    std::cout << std::endl;

    duration = time.execution(do_expensive_loop);
    std::cout << std::endl;
    std::cout << duration << " ms" << std::endl;
    std::cout << std::endl;

    return 0;
}

